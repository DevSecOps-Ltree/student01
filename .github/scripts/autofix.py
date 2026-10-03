"""Propose Copilot fixes for the scanned default-branch commit; never merge them."""
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

REQUIRED = {
    "Python Security Scan (Bandit + Safety)",
    "DAST - OWASP ZAP Scan",
    "DAST - OWASP ZAP Active Scan",
    "CodeQL Analysis (SAST)",
}


def main():
    repo, base, expected = (os.environ[k] for k in ("REPO", "BASE", "TRIGGER_SHA"))
    token = os.environ["GH_TOKEN"]
    prefix = f"https://api.github.com/repos/{repo}"

    def note(message):
        print(message, flush=True)
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
            out.write(message + "\n\n")

    def api(path, method="GET", body=None, allowed=()):
        request = urllib.request.Request(
            prefix + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                data = json.loads(raw)
            except ValueError:
                data = {"message": raw[:300]}
            if exc.code in allowed:
                return exc.code, data
            raise RuntimeError(f"{method} {path}: HTTP {exc.code}: "
                               f"{data.get('message', 'API request failed')}") from None

    def unchanged():
        _, ref = api('/git/ref/heads/' + urllib.parse.quote(base, safe=""))
        if ref['object']['sha'] != expected:
            raise RuntimeError("Default branch changed; rerun against its completed scans.")

    unchanged()
    runs = []
    for page in range(1, 11):
        _, data = api(f'/actions/runs?head_sha={expected}&per_page=100&page={page}')
        runs.extend(data['workflow_runs'])
        if len(data['workflow_runs']) < 100:
            break
    latest = {}
    for run in sorted(runs, key=lambda r: (r['run_number'], r.get('run_attempt', 1)), reverse=True):
        if run['name'] in REQUIRED and run['head_branch'] == base and run['event'] in ('push', 'workflow_dispatch', 'schedule'):
            latest.setdefault(run['name'], run)
    waiting, failed = [], []
    for name in sorted(REQUIRED):
        run = latest.get(name)
        if not run or run['status'] != 'completed':
            waiting.append(name)
        elif run['conclusion'] != 'success':
            failed.append(name)
    if failed:
        raise RuntimeError('Required scans did not succeed: ' + ', '.join(failed))
    if waiting:
        note('Waiting for scans: ' + ', '.join(waiting) + '. A later completion triggers another attempt.')
        return
    note(f'All required scans succeeded for `{expected}`.')
    branch = 'proposed-fixes-' + expected[:12]
    _, prs = api('/pulls?' + urllib.parse.urlencode({'state': 'all', 'head': repo.split('/')[0]+':'+branch, 'base': base}))
    if prs:
        note('A review PR already exists for this scanned commit: ' + prs[0]['html_url'])
        return
    alerts = []
    for page in range(1, 11):
        _, batch = api('/code-scanning/alerts?' + urllib.parse.urlencode({
            'state': 'open', 'ref': 'refs/heads/'+base, 'per_page': 100, 'page': page}))
        alerts.extend(batch)
        if len(batch) < 100:
            break
    candidates = sorted((a for a in alerts if a['tool']['name'] == 'CodeQL'
                         and a['rule']['severity'] in ('error', 'warning')
                         and a['most_recent_instance']['commit_sha'] == expected), key=lambda a:a['number'])
    if not candidates:
        note('No eligible open CodeQL alerts for this commit; no PR needed.')
        return
    fixed = []
    for alert in candidates[:15]:
        number = alert['number']
        endpoint = f'/code-scanning/alerts/{number}/autofix'
        unchanged()
        code, result = api(endpoint, 'POST', allowed=(422,))
        if code == 422:
            note(f'Alert #{number}: no generated fix: {result.get("message", "unsupported alert")}.')
            continue
        # Both 200 (existing) and 202 (generation accepted) are successful requests.
        for attempt in range(18):
            if result.get('status') in ('success', 'failed', 'unsupported'):
                break
            time.sleep(10)
            _, result = api(endpoint, allowed=(404,))
        if result.get('status') != 'success':
            note(f'Alert #{number}: Autofix status `{result.get("status", "unavailable")}`.')
            continue
        unchanged()
        code, _ = api('/git/ref/heads/' + branch, allowed=(404,))
        if code == 404:
            api('/git/refs', 'POST', {'ref': 'refs/heads/'+branch, 'sha': expected})
        code, result = api(endpoint+'/commits', 'POST', {
            'target_ref': 'refs/heads/'+branch,
            'message': f'Copilot Autofix for code scanning alert #{number}'}, allowed=(422,))
        if code == 422:
            note(f'Alert #{number}: could not apply suggestion: {result.get("message")}.')
            continue
        fixed.append(number)
        note(f'Committed Copilot suggestion for alert #{number}.')
        if len(fixed) == 1:
            break
    if not fixed:
        raise RuntimeError('Alerts exist but no fixes were generated; no PR created. See statuses above.')
    unchanged()
    _, comparison = api(f'/compare/{base}...{branch}')
    if not comparison.get('files'):
        raise RuntimeError('Suggested branch has no file changes; refusing an empty PR.')
    body = (f'Copilot Autofix suggestions for CodeQL findings on commit `{expected}`.\n\n'
            + '\n'.join(f'- https://github.com/{repo}/security/code-scanning/{n}' for n in fixed)
            + '\n\nReview the diff and validate behavior before merging. These suggestions do not claim to fix every scan finding.\n'
            + '\nCreated by the lab AutoFix workflow after all required scan workflows completed successfully.')
    _, pr = api('/pulls', 'POST', {'head': branch, 'base': base,
        'title': 'Proposed security fixes (Copilot Autofix)', 'body': body})
    note('Review PR: ' + pr['html_url'])


if __name__ == '__main__':
    main()
