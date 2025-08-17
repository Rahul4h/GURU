# app/utils.py
import requests
from collections import Counter

def get_user_submissions(handle):
    url = f"https://codeforces.com/api/user.status?handle={handle}&from=1&count=10000"
    resp = requests.get(url, timeout=15)
    if resp.status_code == 200:
        data = resp.json()
        if data.get('status') == 'OK':
            return data['result']
    return []

def analyze_user_submissions(submissions):
    """
    Return (tag_scores_list, avg_rating, solved_set)
    tag_scores_list = [(tag, weakness_score), ...] sorted desc (weaker first)
    weakness_score = 1 - success_rate
    """
    correct = Counter()
    wrong = Counter()
    total = Counter()
    rating_list = []
    solved = set()

    for s in submissions:
        if 'problem' not in s:
            continue
        prob = s['problem']
        prob_id = f"{prob.get('contestId')}/{prob.get('index')}"
        verdict = s.get('verdict')
        tags = prob.get('tags', [])
        rating = prob.get('rating')
        if verdict == 'OK':
            solved.add(prob_id)
            for t in tags:
                correct[t] += 1
                total[t] += 1
            if rating:
                rating_list.append(rating)
        elif verdict in ('WRONG_ANSWER', 'TIME_LIMIT_EXCEEDED', 'RUNTIME_ERROR', 'COMPILATION_ERROR'):
            for t in tags:
                wrong[t] += 1
                total[t] += 1

    tag_scores = []
    for t in total:
        succ = correct[t]
        tot = total[t]
        success_rate = succ / tot if tot > 0 else 0.0
        weakness = round(1 - success_rate, 4)
        tag_scores.append((t, weakness))

    tag_scores.sort(key=lambda x: x[1], reverse=True)
    avg_rating = int(sum(rating_list) / len(rating_list)) if rating_list else None

    return tag_scores, avg_rating, solved
