"""Read only the original update's task, never accept a supplied task ID."""

import json

from .hostprep import Command, STATE
from .packagecontents import require
from .packageguards import INTENT
from .packagejob import FIELDS
from .packagesubmit import observe_submission, read_active_job, snapshot
from .tokenchange import real_token_change


def collect_status(prep):
    report = {"format": 1, "operation": "package-update-status", "result": "inspection-required",
              "host_changes_attempted": False, "automatic_retry": False, "upgrade_completed": False,
              "current_service_health": "not-checked", "restoration_authorized": False}
    path = STATE + "/" + INTENT + ".json"
    original = prep.runner
    try:
        with prep._lock():
            if prep.files.info(path) is None:
                report["result"] = "no-active-update-record-not-a-health-verdict"
                return report
            job, before = read_active_job(prep.files)
        def readonly(command):
            require(type(command) is Command and command.env == Command(("unused",)).env
                    and command.capture_stderr is False
                    and type(command.timeout) in {int, float} and 0 < command.timeout <= 5
                    and command.argv == ("systemctl", "show", "--all", job.unit, "-p", ",".join(FIELDS)))
            return original(command)
        prep.runner = readonly
        observed = observe_submission(prep, job)
        with prep._lock():
            require(snapshot(prep.files, path, 0o600) == before)
        report.update(result=observed["result"], observation=observed)
    except (EOFError, KeyboardInterrupt):
        report["result"] = "observation-interrupted-task-not-stopped"
    except Exception:
        pass
    finally:
        prep.runner = original
    return report


def run_package_status(*, factory=real_token_change, json_output=False):
    try:
        with factory() as tokens:
            report = collect_status(tokens.prep)
    except Exception:
        report = {"format": 1, "operation": "package-update-status", "result": "inspection-required",
                  "host_changes_attempted": False, "automatic_retry": False, "upgrade_completed": False}
    if not json_output:
        print("只读查询原更新任务；安装命令成功不等于恢复完成，没有任务记录也不证明节点健康。")
        print("本命令不继续安装或恢复；异常时保留现场，不重试、重启或解除保护。")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["result"] in {"no-active-update-record-not-a-health-verdict",
                                    "running-or-queued", "command-exited-success"} else 1
