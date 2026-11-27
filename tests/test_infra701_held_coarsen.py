"""INFRA-701: over-budget held paths are widened to ancestors (safe direction) instead of deferring forever."""
import scan

ROOT = "/share/x/bkup"


def test_within_budget_is_unchanged():
    held = [ROOT + "/a/b/c", ROOT + "/d"]
    assert scan._coarsen_held(held, ROOT, 10, budget=1000) == sorted(held)


def test_over_budget_widens_deepest_first_and_fits():
    held = [f"{ROOT}/daily/{d}/crontabs" for d in range(10)] + [ROOT + "/old"]
    out = scan._coarsen_held(held, ROOT, 1000, budget=11_000)   # 11 x 1000 = 11000 fits as is
    assert out == sorted(held)
    out = scan._coarsen_held(held, ROOT, 1000, budget=5_000)    # must shrink to <= 5 paths
    assert out is not None and len(out) * 1000 <= 5_000
    assert all(any(h == o or h.startswith(o + "/") for o in out) for h in held)   # every held path still covered


def test_depth_one_over_budget_defers():
    assert scan._coarsen_held([ROOT + "/a", ROOT + "/b"], ROOT, 10_000, budget=1_000) is None
