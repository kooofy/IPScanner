# -*- coding: utf-8 -*-
"""扫描节流与礼貌模式（v2.1 §2.4）：并发上限 + 顺序随机化 + 包速率上限。

为什么要有这一层
----------------
企业网里全速扫端口会被 IDS 直接判定成扫描攻击（`PRODUCT_ADVISORY.md` §4.1
「扫描节流与礼貌模式」行）。改造前本项目的节流状态是**硬编码**：
`ports._PORT_POOL_WORKERS = 384`、引擎 `max_threads = min(50, len(all_ips))`、
异步路径 `Semaphore(1024)` —— 没有「上限是多少」的用户可调概念，
也没有顺序随机化与包速率上限。

本模块把这三件事抽成**一个纯数据对象 + 三个可独立单测的部件**：

1. `ThrottlePolicy` —— 一次扫描用哪个档（`fast` / `balanced` / `polite`），
   三个字段都是**语言无关的规范值**（见下方"规范值"节）；
2. `TokenBucket` —— 令牌桶限速，`clock` / `sleep` 可注入 ⇒ 单测用**假时钟**
   推进，不真 sleep；
3. `deliver()` —— 按档投递 targets：先按需随机化顺序，再用**本地**线程池
   把同时在飞数压到 `max_concurrency` 以内。

设计约束（与项目铁律对齐）
--------------------------
- **零 PyQt / 零第三方 / 零网络**：只用标准库 `random` / `time` / `threading` /
  `concurrent.futures`；
- **`fast` 档必须与改造前逐字节等价**：`max_concurrency = 0` 表示"不额外设限"，
  于是 `fast` 下 `deliver()` 的上限等于任务数、不随机化、不限速 ——
  调用方的行为与没有本模块时完全一致。**这不是懒，是回归防线**：
  任何"顺手给 fast 也加个默认上限"的改动都会让老用户的扫描结果变样；
- **顺序随机化用独立 `random.Random` 实例**，绝不摸全局 `random` 状态
  （否则会静默改变别的模块的随机行为，且 seed 无法复现）。

规范值（绝不落 `tr()` 结果）
---------------------------
档位名 `fast` / `balanced` / `polite` 是**规范值**，可直接落审计库；
显示名走 `scanner.constants.throttle_label()` 惰性翻译。
`audit_detail()` 只产出规范值（int / bool / ascii 名），切语言逐字节相同。
"""
import concurrent.futures
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from app_logging import get_logger

_log = get_logger(__name__)

# ── 档位规范值 ────────────────────────────────────────────────────────────

POLICY_FAST = "fast"
POLICY_BALANCED = "balanced"
POLICY_POLITE = "polite"

#: 全部档位规范值（CLI `choices` / GUI 下拉都从这里取，别再各写一份字面量）。
POLICY_NAMES = (POLICY_FAST, POLICY_BALANCED, POLICY_POLITE)

#: 默认档：与改造前行为完全一致。用户没显式选档时用它，
#: 这样「不传 --throttle」和「改造前」结果逐条一致。
DEFAULT_POLICY = POLICY_FAST

#: 0 = 不额外设限。刻意选 0 而不是 None：审计库里 0 一眼能看出"这个档不限"，
#: 而 None 会被 JSON 序列化成 null、和"没记录"分不开。
NO_LIMIT = 0


@dataclass(frozen=True)
class ThrottlePolicy:
    """一次扫描的礼貌档。

    Attributes:
        name: 档位规范值（``fast`` / ``balanced`` / ``polite``）。
        max_concurrency: 同时在飞上限；``0`` = 不额外设限（用调用方自身并发）。
        shuffle: 是否在投递前随机化顺序（可注入 seed 复现）。
        packets_per_minute: 每分钟放行的包数上限；``0`` = 不限速。
    """
    name: str
    max_concurrency: int
    shuffle: bool
    packets_per_minute: int

    @property
    def rate_limited(self) -> bool:
        """这一档是否启用了包速率上限。"""
        return self.packets_per_minute > 0

    def describe(self) -> str:
        """一行人类可读摘要（仅日志用；审计一律走 `audit_detail()`）。"""
        if self.name == POLICY_FAST:
            return "fast（不额外设限，与改造前一致）"
        return (f"{self.name}（并发≤{self.max_concurrency}，"
                f"随机化={'开' if self.shuffle else '关'}，"
                f"≤{self.packets_per_minute} 包/分）")

    def audit_detail(self) -> Dict[str, Any]:
        """落审计库用的规范值 dict（`audit_detail()` 的实例版）。"""
        return {
            "policy": self.name,
            "max_concurrency": self.max_concurrency,
            "shuffle": self.shuffle,
            "packets_per_minute": self.packets_per_minute,
        }


#: 三档预设。数值取的是"能讲出理由"的量级，不是玄调参：
#: - `fast`     = 改造前原样（并发/顺序/速率全不设限）；
#: - `balanced` = 把探测并发压到 64（约为端口池 384 的 1/6），
#:                6000 包/分 ≈ 每秒 100 个探测 —— 单 /24 扫完仍在分钟级；
#: - `polite`   = 16 并发 + 600 包/分（每秒 10 个），单 /24 约 10 分钟。
#:                这是"IDS 不会告警"的量级：多数设备的告警阈值在
#:                「每秒数十个 SYN / 每分数百个包」附近，10/s 留足余量。
POLICIES: Dict[str, ThrottlePolicy] = {
    POLICY_FAST: ThrottlePolicy(POLICY_FAST, NO_LIMIT, False, NO_LIMIT),
    POLICY_BALANCED: ThrottlePolicy(POLICY_BALANCED, 64, True, 6000),
    POLICY_POLITE: ThrottlePolicy(POLICY_POLITE, 16, True, 600),
}


def resolve_policy(name: Optional[str] = None) -> ThrottlePolicy:
    """档位名 → `ThrottlePolicy`；``None`` / 空串 → 默认档（`fast`）。

    未知档位抛 `ValueError` 而不是静默回退：CLI 的 `choices` 已经挡掉绝大多数，
    走到这里说明是**库调用方**传了错值 —— 静默回退会让「我以为在 polite 档」
    和「其实全速扫」之间产生危险的误解。
    """
    if not name:
        return POLICIES[DEFAULT_POLICY]
    key = str(name).strip().lower()
    try:
        return POLICIES[key]
    except KeyError:
        raise ValueError(
            f"未知的礼貌档 {name!r}；可用：{' / '.join(POLICY_NAMES)}"
        ) from None


def audit_detail(policy: Optional[ThrottlePolicy] = None) -> Dict[str, Any]:
    """当前档位的规范值描述（落审计库用）。

    产出**只有** int / bool / ascii 档名 —— 切界面语言逐字节相同，
    因此可以直接 `json.dumps` 进 `audit_log` 的 `detail` 列。
    """
    if policy is None:
        policy = current_policy()
    return policy.audit_detail()


# ── 顺序随机化 ────────────────────────────────────────────────────────────

def shuffled(items: Iterable[Any], seed: Optional[Any] = None) -> List[Any]:
    """返回打乱后的列表；``seed`` 给定时结果**可复现**。

    用**独立的 `random.Random`** 而不是模块级 `random.shuffle`：
    后者会动全局随机状态，让别的模块（以及别的测试）的随机行为静默改变。
    这里 seed 相同 ⇒ 输出逐字节相同，单测才能断言"不等于声明序但可复现"。
    """
    rng = seed if isinstance(seed, random.Random) else random.Random(seed)
    out = list(items)
    rng.shuffle(out)
    return out


def prepare_targets(seq: Iterable[Any], policy: Optional[ThrottlePolicy] = None,
                    seed: Optional[Any] = None) -> List[Any]:
    """按档位预处理投递序列（目前只做顺序随机化）。

    `fast` 档原样返回 —— **顺序不变**是 fast 兼容旧行为的一部分。

    🔴 `policy=None` 取**当前激活档**（`current_policy()`），不是默认档：
    调用方（`scanner.engine.scan()`）不显式传档，靠的就是外面那层
    `active_policy()`；取默认档会让"礼貌模式已开启"悄悄变成 no-op ——
    这正是本函数被 engine 接线时抓出来的 bug（见 engine 的 ThrottleOrderTest）。
    """
    if policy is None:
        policy = current_policy()
    items = list(seq)
    if not policy.shuffle:
        return items
    return shuffled(items, seed=seed)


# ── 令牌桶（clock / sleep 可注入 ⇒ 假时钟单测，不真 sleep） ────────────────

#: 令牌比较的浮点容差。连续累加 `now += wait` 会让时钟停在一个"差 4e-16 就该
#: 补满"的位置上（实测 0.30000000000000004 + 0.1 → 0.4，补出 0.9999999999999996），
#: 没有容差就会算出 `4.44e-17` 秒的等待 —— 那比 0.4 的 ULP 还小，加回去时钟
#: 纹丝不动，防挂死护栏于是**误报**。容差取 1e-9：远大于浮点噪声，
#: 远小于任何有意义的速率调整。
_TOL = 1e-9

#: 真正需要等待时的最短睡眠。1µs 在任何真实时钟上都可表示，
#: 因此 `clock()` 一定前进 —— 防挂死护栏不会误报。
_MIN_WAIT = 1e-6


class TokenBucket:
    """令牌桶限速器。

    `clock` 与 `sleep` 都可注入，这是**可测性的关键**：单测传一个假时钟、
    并让 `sleep` 去推进那个假时钟，就能在零真实时间消耗下验证
    「给定 rate，单位时间内放行数 ≤ 上限」。

    🔴 **防挂死护栏**：如果 `sleep()` 返回后 `clock()` 没有前进（典型原因是
    注入了一个不自增时钟的假 sleep），本类抛 `RuntimeError` 而不是空转。
    理由见仓库长期记忆：把测试挂死比把测试弄失败恶劣得多 ——
    失败会红，挂死能把 CI 挂满 6 小时。护栏本身也吃 `_TOL` 容差，
    否则上面那种"补出 0.9999999999999996"的正常情形会被它误杀。
    """

    def __init__(self, rate_per_minute: float, *, capacity: float = 1.0,
                 initial: Optional[float] = None,
                 clock=time.monotonic, sleep=time.sleep):
        if rate_per_minute <= 0:
            raise ValueError(f"速率必须为正，收到 {rate_per_minute!r}")
        if capacity <= 0:
            raise ValueError(f"桶容量必须为正，收到 {capacity!r}")
        self.rate_per_minute = float(rate_per_minute)
        self.capacity = float(capacity)
        self._tokens = self.capacity if initial is None else float(initial)
        if not 0 <= self._tokens <= self.capacity:
            raise ValueError("初始令牌数必须在 [0, capacity] 区间内")
        self._per_second = self.rate_per_minute / 60.0
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    # -- 内部 --
    def _refill_locked(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity,
                               self._tokens + elapsed * self._per_second)
            self._last = now

    # -- 公开 --
    @property
    def tokens(self) -> float:
        """当前可用令牌数（读数前先按时钟补一次）。"""
        with self._lock:
            self._refill_locked()
            return self._tokens

    def seconds_until(self, n: int = 1) -> float:
        """还要等多少秒才拿得到 ``n`` 枚令牌（不睡眠、不改状态语义）。"""
        if n <= 0:
            return 0.0
        with self._lock:
            self._refill_locked()
            if self._tokens + _TOL >= n:
                return 0.0
            return (n - self._tokens) / self._per_second

    def try_acquire(self, n: int = 1) -> bool:
        """非阻塞取令牌；取不到返回 ``False``（不睡眠）。"""
        if n <= 0:
            return True
        with self._lock:
            self._refill_locked()
            if self._tokens + _TOL >= n:
                # 容差内扣成 0 而不是负数：负令牌会让下一次等待时间翻倍，
                # 把速率悄悄压到档位值以下。
                self._tokens = max(0.0, self._tokens - n)
                return True
            return False

    def acquire(self, n: int = 1) -> None:
        """阻塞直到取到 ``n`` 枚令牌。

        🔴 见类 docstring 的防挂死护栏：时钟不前进时抛 `RuntimeError`。
        """
        if n <= 0:
            return
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens + _TOL >= n:
                    self._tokens = max(0.0, self._tokens - n)
                    return
                wait = max((n - self._tokens) / self._per_second, _MIN_WAIT)
            before = self._clock()
            self._sleep(wait)
            after = self._clock()
            if after <= before + before * 1e-12:
                raise RuntimeError(
                    "令牌桶等待期间时钟没有前进（sleep 与 clock 不是同一时间基）"
                    "—— 终止而非空转，避免把进程挂死"
                )


class InFlightCounter:
    """同时在飞任务计数器（`deliver()` 的记账器）。

    `peak` 是整轮观测到的最大在飞数 —— 单测断言它 `<= policy.max_concurrency`
    就是"上限真的生效了"的客观证据，比"看起来有上限"可靠。
    用 `with` 语法，天然异常安全。
    """

    def __init__(self) -> None:
        self.current = 0
        self.peak = 0
        self._lock = threading.Lock()

    def __enter__(self) -> "InFlightCounter":
        with self._lock:
            self.current += 1
            if self.current > self.peak:
                self.peak = self.current
        return self

    def __exit__(self, *exc) -> bool:
        with self._lock:
            self.current -= 1
        return False


# ── 按档投递 ──────────────────────────────────────────────────────────────

def _run_one(work, key, bucket, counter):
    # 取令牌放在**进计数器之前**：等令牌的线程不应该算"在飞"，
    # 否则 polite 档下排队的时间会把在飞数顶到上限之外。
    if bucket is not None:
        bucket.acquire(1)
    if counter is None:
        return work(key)
    with counter:
        return work(key)


def deliver(work, targets: Iterable[Any], *, policy: Optional[ThrottlePolicy] = None,
            seed: Optional[Any] = None, counter: Optional[InFlightCounter] = None,
            bucket: Optional[TokenBucket] = None) -> List[Any]:
    """按礼貌档投递 ``targets``，返回与**（可能已打乱的）投递序**对齐的结果列表。

    Args:
        work: ``work(key) -> result``，对单个 target 做的事。
        targets: 待投递的 target 序列。
        policy: 档位；``None`` → 当前激活档（见 `active_policy`）。
        seed: 随机化种子（可复现）。
        counter: 记账器；给了就统计在飞峰值（生产可直接传 `InFlightCounter()`）。
        bucket: 令牌桶；``None`` → 用当前激活桶（`fast` 档下是 ``None`` = 不限速）。

    🔴 **不要**把这里的线程池改成"注入的 mock 池"。本函数用**自己创建的、
    必定会真实完成**的本地 `ThreadPoolExecutor`，所以 `as_completed()` 一定能等到。
    仓库里有过一次教训：mock 池的 `submit()` 返回永不完成的 future，
    `as_completed()` 于是 `event.wait()` 永久阻塞，把 CI 挂死 6 小时。
    """
    if policy is None:
        policy = current_policy()
    items = prepare_targets(targets, policy, seed=seed)
    if not items:
        return []

    if bucket is None:
        bucket = _active_bucket()

    limit = policy.max_concurrency or len(items)
    limit = max(1, min(limit, len(items)))

    results: List[Any] = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=limit, thread_name_prefix="throttled") as ex:
        fut_to_idx = {
            ex.submit(_run_one, work, key, bucket, counter): i
            for i, key in enumerate(items)
        }
        # 本地池、future 一定会完成 ⇒ `as_completed` 必然返回（见上方红线注释）。
        for fut in concurrent.futures.as_completed(fut_to_idx):
            results[fut_to_idx[fut]] = fut.result()
    return results


# ── 进程内激活档（供 ports / async_ports 在热路径上读） ───────────────────

_active_lock = threading.Lock()
_active_policy: ThrottlePolicy = POLICIES[DEFAULT_POLICY]
#: 当前放行闸门用的桶；``None`` = 不限速（`fast` 档即此状态）。
_bucket: Optional[TokenBucket] = None


class _PolicyContext:
    """`active_policy()` 的返回值：**进入前就已生效**，退出时恢复旧档。

    刻意让 `active_policy()` 在返回对象时就把状态装好（而不是等 `__enter__`）：
    调用方可能只写 `throttle.active_policy(p)` 而漏掉 `with`，那种写法下
    依然想要"这次扫描按 p 走"。代价是必须靠 `__exit__` 恢复，所以
    `_PolicyContext` 同时记住**旧档和旧桶**，见下方 `active_policy()`。
    """

    def __init__(self, activated: ThrottlePolicy, previous: ThrottlePolicy,
                 previous_bucket: Optional[TokenBucket]) -> None:
        self.activated = activated
        self._previous = previous
        self._previous_bucket = previous_bucket

    def __enter__(self) -> ThrottlePolicy:
        return self.activated

    def __exit__(self, *exc) -> bool:
        # 🔴 恢复的是**上一层**的档与桶，不是默认档。写成 reset_throttle() 会让
        # 嵌套激活把外层档一起抹掉（v1 就犯过这个错，被下面两个嵌套测试抓到）。
        _install(self._previous, self._previous_bucket)
        return False


def _install(policy: ThrottlePolicy, bucket: Optional[TokenBucket]) -> None:
    global _active_policy, _bucket
    with _active_lock:
        _active_policy = policy
        _bucket = bucket


def active_policy(policy: Optional[ThrottlePolicy] = None) -> _PolicyContext:
    """把 ``policy`` 设为激活档并返回恢复器（可作 `with` 用）。

    嵌套安全：记住上一层档位**和它的限速桶**，退出时原样装回。
    退出**一定**恢复 —— 否则一次 polite 扫描的限速桶会漏到后续所有扫描上，
    那是"悄悄把工具变慢"的故障。
    """
    if policy is None:
        policy = resolve_policy()
    with _active_lock:
        previous_policy = _active_policy
        previous_bucket = _bucket
    new_bucket = _make_bucket(policy) if policy.rate_limited else None
    _install(policy, new_bucket)
    return _PolicyContext(policy, previous_policy, previous_bucket)


def _make_bucket(policy: ThrottlePolicy) -> TokenBucket:
    return TokenBucket(policy.packets_per_minute)


def current_policy() -> ThrottlePolicy:
    """当前激活档（默认 `fast`）。热路径可安全调用。"""
    return _active_policy


def _active_bucket() -> Optional[TokenBucket]:
    return _bucket


def reset_throttle() -> None:
    """恢复默认档并丢弃限速桶。**测试隔离用**；正常流程不需要。

    与 `ports.reset_async_engine_state()` 同口径：凡是跨模块共享的可变状态，
    都要有一个测试能调的复位函数，否则一次泄漏会让后续用例集体行为异常。
    """
    _install(POLICIES[DEFAULT_POLICY], None)


def throttle_gate() -> None:
    """按当前档放行一个包（不限速时是 no-op）。

    `ports` / `async_ports` 的探测热路径在发包前调它。
    `fast` 档（默认）下 `_bucket is None` ⇒ 只有一次全局加载 + None 判断，
    对吞吐的影响可以忽略；只有显式选了 `balanced` / `polite` 才会真正阻塞。
    """
    bucket = _bucket
    if bucket is not None:
        bucket.acquire(1)


def concurrency_for(default: int) -> int:
    """把默认并发上限按当前档夹紧。

    ``default`` 是调用方自身的并发设置（如 `async_ports.DEFAULT_CONCURRENCY`）；
    当前档不设限时原样返回 —— 这就是 `fast` 档与改造前逐字节等价的保证。
    """
    cap = _active_policy.max_concurrency
    if not cap or cap <= 0:
        return default
    return max(1, min(default, cap))


def shuffle_for(items: Sequence[Any], seed: Optional[Any] = None) -> List[Any]:
    """按当前档决定是否打乱 ``items``（`prepare_targets` 的当前档版）。"""
    return prepare_targets(items, _active_policy, seed=seed)
