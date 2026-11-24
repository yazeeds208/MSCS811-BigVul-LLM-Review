"""Run the original evaluation with a longer, recorded client wait timeout.

Prompts, model, generation, scoring, and the original runners are unchanged.
Use a new output folder. The default wait is 600 seconds per generation request.
"""
import argparse
import json
import sys
from pathlib import Path

import run_mscs811_pilot as pilot
import run_mscs811_evaluation as evaluation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request-timeout', type=int, default=600)
    parser.add_argument('--archive', type=Path, default=evaluation.ROOT / 'MSCS811_BigVul_Evaluation.zip')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--model', type=Path)
    parser.add_argument('--server', type=Path)
    args = parser.parse_args()
    if args.request_timeout < 1:
        parser.error('--request-timeout must be positive.')
    output = args.output.resolve()
    settings_path = output / 'client_settings.json'
    settings = {
        'request_timeout_seconds': args.request_timeout,
        'wrapper_sha256': pilot.digest(Path(__file__)),
        'note': 'Client wait timeout only. The frozen model, prompts, generation, and scoring settings are unchanged.',
    }
    if settings_path.exists():
        if json.loads(settings_path.read_text()) != settings:
            raise ValueError('Output folder uses different client wait settings. Use a new folder.')
    elif output.exists() and any(output.iterdir()):
        raise ValueError('Use a new output folder; keep previous 90-second runs unchanged.')

    original_http = pilot.LOCAL_HTTP
    class LongerWait:
        def open(self, request, timeout=None):
            return original_http.open(request, timeout=args.request_timeout if timeout == 90 else timeout)
    pilot.LOCAL_HTTP = LongerWait()

    original_write = evaluation.atomic_json
    def record_settings(path, value):
        original_write(path, value)
        if path.name == 'run_manifest.json':
            original_write(settings_path, settings)
    evaluation.atomic_json = record_settings

    forwarded = ['--archive', str(args.archive), '--output', str(output)]
    for option in ('model', 'server'):
        if getattr(args, option) is not None:
            forwarded.extend(['--' + option, str(getattr(args, option))])
    sys.argv = [str(evaluation.ROOT / 'run_mscs811_evaluation.py'), *forwarded]
    print(f'Generation request timeout: {args.request_timeout} seconds. Original protocol retained.', flush=True)
    evaluation.main()


if __name__ == '__main__':
    main()
