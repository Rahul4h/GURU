

from django.http import JsonResponse
from django.db import models

import json
import requests
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import render, get_object_or_404, redirect
from .models import Post,Comment, Reaction,CommentReaction
import requests, time
from django.core.cache import cache  # ✅ add this


@login_required
def blog_page(request):
    posts = Post.objects.all().order_by('-created_at')
    return render(request, 'blog.html', {'posts': posts})


# app/views.py


from django.shortcuts import render

def contact_page(request):
    return render(request, 'contact.html')


@login_required
def blog_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    # Fetch top-level comments only
    comments = (
        post.comments.filter(parent__isnull=True)
        .prefetch_related("reactions", "replies__reactions", "replies__replies__reactions")
        .order_by("-created_at")
    )
    post_reactions = post.reactions.values("reaction_type").annotate(count=models.Count("id"))

    if request.method == "POST":
        # Add comment or reply
        if "comment" in request.POST:
            parent_id = request.POST.get("parent_id")
            parent_comment = Comment.objects.get(id=parent_id) if parent_id else None
            Comment.objects.create(
                post=post,
                user=request.user,
                content=request.POST["comment"],
                parent=parent_comment
            )
            return redirect("blog_detail", post_id=post.id)

        # React to post
        if "reaction_post" in request.POST:
            reaction_type = request.POST["reaction_post"]
            Reaction.objects.update_or_create(
                post=post,
                user=request.user,
                defaults={"reaction_type": reaction_type},
            )
            return redirect("blog_detail", post_id=post.id)

        # React to comment/reply
        if "reaction_comment" in request.POST:
            comment_id = request.POST.get("comment_id")
            reaction_type = request.POST.get("reaction_comment")
            comment = Comment.objects.get(id=comment_id)
            CommentReaction.objects.update_or_create(
                comment=comment,
                user=request.user,
                defaults={"reaction_type": reaction_type},
            )
            return redirect("blog_detail", post_id=post.id)

    # Recursive helper to attach reaction counts
    def add_reaction_counts(comment):
        comment.reaction_counts = (
            comment.reactions.values("reaction_type")
            .annotate(count=models.Count("id"))
        )
        for reply in comment.replies.all():
            add_reaction_counts(reply)

    # Attach reactions to all comments & replies
    for comment in comments:
        add_reaction_counts(comment)

    return render(request, "blog_detail.html", {
        "post": post,
        "comments": comments,
        "post_reactions": post_reactions,
    })




@login_required
def index(request):
    return render(request, 'index.html')

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json, requests
from collections import defaultdict, Counter

@csrf_exempt
def analyze_handle(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            handle = data.get('handle')

            # --- Get profile info ---
            profile_url = f"https://codeforces.com/api/user.info?handles={handle}"
            profile_resp = requests.get(profile_url).json()

            if profile_resp['status'] != 'OK':
                return JsonResponse({'error': 'Invalid handle'}, status=400)

            user = profile_resp['result'][0]

            # --- Get rating history ---
            rating_url = f"https://codeforces.com/api/user.rating?handle={handle}"
            rating_resp = requests.get(rating_url).json()

            rating_data = []
            if rating_resp['status'] == 'OK':
                for entry in rating_resp['result']:
                    rating_data.append({
                        'contest': entry['contestName'],
                        'rating': entry['newRating'],
                        'timestamp': entry['ratingUpdateTimeSeconds']
                    })

            # --- Get submission history ---
            submission_url = f"https://codeforces.com/api/user.status?handle={handle}&from=1&count=10000"
            submission_resp = requests.get(submission_url).json()

            tag_counter = Counter()
            solved_set = set()
            rating_buckets = {
                'under_1200': 0,
                '1200_1399': 0,
                '1400_1599': 0,
                '1600_1899': 0
            }

            if submission_resp['status'] == 'OK':
                for sub in submission_resp['result']:
                    if sub.get('verdict') == 'OK':
                        problem = sub['problem']
                        problem_id = f"{problem.get('contestId')}-{problem.get('index')}"

                        # Avoid duplicates
                        if problem_id in solved_set:
                            continue
                        solved_set.add(problem_id)

                        # Count tags
                        tags = problem.get('tags', [])
                        tag_counter.update(tags)

                        # Count by rating
                        rating = problem.get('rating')
                        if rating:
                            if rating < 1200:
                                rating_buckets['under_1200'] += 1
                            elif rating < 1400:
                                rating_buckets['1200_1399'] += 1
                            elif rating < 1600:
                                rating_buckets['1400_1599'] += 1
                            elif rating < 1900:
                                rating_buckets['1600_1899'] += 1

            # Sort tags by most solved
            sorted_tags = tag_counter.most_common()

            return JsonResponse({
                'handle': user['handle'],
                'rank': user.get('rank', 'unrated'),
                'rating': user.get('rating', 'N/A'),
                'maxRank': user.get('maxRank', 'unrated'),
                'maxRating': user.get('maxRating', 'N/A'),
                'avatar': user.get('titlePhoto', ''),
                'ratingHistory': rating_data,
                'tagStats': sorted_tags,
                'ratingBuckets': rating_buckets
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

@login_required
def suggestions_page(request):
    return render(request, 'suggestions.html')



import requests

def get_user_submissions(handle):
    url = f"https://codeforces.com/api/user.status?handle={handle}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data['result']
    return []

from collections import Counter

from collections import Counter

from collections import defaultdict, Counter

def analyze_user(submissions):
    correct_tags = Counter()
    wrong_tags = Counter()
    total_attempts = Counter()
    rating_dist = []
    solved_problems = set()

    for sub in submissions:
        if 'problem' not in sub:
            continue
        prob = sub['problem']
        tags = prob.get('tags', [])
        rating = prob.get('rating', None)
        prob_id = f"{prob['contestId']}/{prob['index']}"

        verdict = sub.get('verdict')
        if verdict == 'OK':
            solved_problems.add(prob_id)
            for tag in tags:
                correct_tags[tag] += 1
                total_attempts[tag] += 1
            if rating:
                rating_dist.append(rating)
        elif verdict in ['WRONG_ANSWER', 'TIME_LIMIT_EXCEEDED', 'RUNTIME_ERROR']:
            for tag in tags:
                wrong_tags[tag] += 1
                total_attempts[tag] += 1

    # Compute tag weakness score
    tag_scores = []
    for tag in total_attempts:
        correct = correct_tags[tag]
        total = total_attempts[tag]
        success_rate = correct / total if total > 0 else 0
        weakness_score = 1 - success_rate  # Higher = weaker
        tag_scores.append((tag, round(weakness_score, 3)))

    # Sort by weakness (higher score = weaker tag)
    tag_scores.sort(key=lambda x: x[1], reverse=True)

    avg_rating = int(sum(rating_dist) / len(rating_dist)) if rating_dist else 1200

    return tag_scores, avg_rating, solved_problems



def get_problemset():
    res = requests.get("https://codeforces.com/api/problemset.problems")
    return res.json()['result']['problems']


from collections import defaultdict, Counter

def recommend_problems_by_range(submissions, problems, solved_problems, ranges, max_per_tag=20):
    all_range_recs = {}
    used_ids = set()

    for r in ranges:
        lower, upper = r

        # 1. Filter submissions in this range
        range_subs = []
        for sub in submissions:
            if 'problem' not in sub or 'verdict' not in sub:
                continue
            prob = sub['problem']
            rating = prob.get('rating')
            if rating is None or not (lower <= rating <= upper):
                continue
            range_subs.append(sub)

        # 2. Analyze tag weakness in this range
        correct_tags = Counter()
        wrong_tags = Counter()
        total_attempts = Counter()

        for sub in range_subs:
            prob = sub['problem']
            tags = prob.get('tags', [])
            verdict = sub.get('verdict')
            if verdict == 'OK':
                for tag in tags:
                    correct_tags[tag] += 1
                    total_attempts[tag] += 1
            elif verdict in ['WRONG_ANSWER', 'TIME_LIMIT_EXCEEDED', 'RUNTIME_ERROR']:
                for tag in tags:
                    wrong_tags[tag] += 1
                    total_attempts[tag] += 1

        tag_scores = []
        for tag in total_attempts:
            correct = correct_tags[tag]
            total = total_attempts[tag]
            success_rate = correct / total if total > 0 else 0
            weakness_score = 1 - success_rate
            tag_scores.append((tag, round(weakness_score, 3)))

        tag_scores.sort(key=lambda x: x[1], reverse=True)  # weak to strong

        # 3. Recommend problems using weak tags in this range
        range_recs = []
        for tag, _ in tag_scores:
            tag_problems = []
            for prob in problems:
                tags = prob.get('tags', [])
                rating = prob.get('rating', 0)
                prob_id = f"{prob['contestId']}/{prob['index']}"

                if prob_id in solved_problems or prob_id in used_ids:
                    continue
                if tag not in tags or not (lower <= rating <= upper):
                    continue

                tag_problems.append({
                    'name': f"{prob['contestId']}-{prob['index']}: {prob['name']}",
                    'tags': tags,
                    'rating': rating,
                    'url': f"https://codeforces.com/problemset/problem/{prob['contestId']}/{prob['index']}",
                    'tag': tag
                })
                used_ids.add(prob_id)

                if len(tag_problems) >= max_per_tag:
                    break

            range_recs.extend(tag_problems)

        all_range_recs[f"{lower}-{upper}"] = {
            'tag_strengths': [{'tag': tag, 'score': score} for tag, score in tag_scores],
            'suggestions': range_recs
        }

    return all_range_recs



from django.http import JsonResponse
import json
@csrf_exempt
def ml_suggestions_view(request):
    if request.method == 'POST':
        body = json.loads(request.body)
        handle = body.get('handle')

        submissions = get_user_submissions(handle)
        problems = get_problemset()
        solved_problems = get_solved_problem_ids(submissions)

        rating_ranges = [
            (800, 1100),
            (1200, 1400),
            (1500, 1600),
            (1600, 1900)
        ]

        recs_by_range = recommend_problems_by_range(submissions, problems, solved_problems, rating_ranges)

        return JsonResponse(recs_by_range)

    
def get_solved_problem_ids(submissions):
    solved = set()
    for sub in submissions:
        if sub.get('verdict') == 'OK' and 'problem' in sub:
            prob = sub['problem']
            solved.add(f"{prob['contestId']}/{prob['index']}")
    return solved


# ==========================
# Django Authentication Views
# ==========================



# =====================================================
# 1️⃣ SIGNUP VIEW — handles user creation & email verify
# =====================================================
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings

# --- Signup ---
def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm = request.POST['confirm']

        if password != confirm:
            messages.error(request, 'Passwords do not match.')
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return redirect('signup')

        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = False  # Deactivate until email verified
        user.save()

        # Generate email verification link
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        #verify_url = f"http://127.0.0.1:8000/verify/{uid}/{token}/"
        verify_url = f"{settings.DOMAIN}/verify/{uid}/{token}/"


        subject = "Verify your email - GURU"
        message = f"Hello {username},\n\nPlease verify your email by clicking the link below:\n{verify_url}\n\nThank you!"
        send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

        messages.success(request, 'Verification email sent! Please check your inbox.')
        return redirect('login')

    return render(request, 'signup.html')


# --- Email Verification ---
def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Email verified successfully! You can now log in.')
        return redirect('login')
    else:
        return render(request, 'email_verification_failed.html')


# --- Login ---
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                messages.success(request, f'Welcome {username}!')
                return redirect('index')
            else:
                messages.error(request, 'Please verify your email first.')
                return redirect('login')
        else:
            messages.error(request, 'Invalid credentials.')
            return redirect('login')
    return render(request, 'login.html')


# --- Logout ---
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')








# app/views.py
import json
import requests
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseBadRequest
from .models import Profile, Post, Tutorial, WeaknessSnapshot
from .forms import ProfilePictureForm, PostForm, TutorialForm
from .utils import get_user_submissions, analyze_user_submissions

@login_required
def profile(request):
    # 1) Ensure Profile exists
    Profile.objects.get_or_create(user=request.user)

    # 2) Codeforces basic info (handle assumed same as username)
    handle = request.user.username
    cf_info = {}
    cf_ratings = []
    try:
        r = requests.get(f"https://codeforces.com/api/user.info?handles={handle}", timeout=10)
        data = r.json()
        if data.get('status') == 'OK':
            cf_info = data['result'][0]
    except Exception:
        cf_info = {}

    try:
        r2 = requests.get(f"https://codeforces.com/api/user.rating?handle={handle}", timeout=10)
        rd = r2.json()
        if rd.get('status') == 'OK':
            cf_ratings = rd['result']
    except Exception:
        cf_ratings = []

    # 3) user's posts & tutorials
    posts = Post.objects.filter(author=request.user).order_by('-created_at')
    tutorials = Tutorial.objects.filter(author=request.user).order_by('-created_at')

    # 4) snapshots (history)
    snapshots = WeaknessSnapshot.objects.filter(user=request.user).order_by('created_at')  # asc for chart

    # forms
    pform = ProfilePictureForm(instance=request.user.profile)
    post_form = PostForm()
    tutorial_form = TutorialForm()

    return render(request, "profile.html", {
        "cf_info": cf_info,
        "cf_ratings": cf_ratings,
        "posts": posts,
        "tutorials": tutorials,
        "snapshots": snapshots,
        "pform": pform,
        "post_form": post_form,
        "tutorial_form": tutorial_form,
    })

@login_required
def update_profile_picture(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")
    p = request.user.profile
    form = ProfilePictureForm(request.POST, request.FILES, instance=p)
    if form.is_valid():
        form.save()
        messages.success(request, "Profile updated.")
    else:
        messages.error(request, "Failed to update profile.")
    return redirect('profile')

@login_required
def add_post(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")
    form = PostForm(request.POST, request.FILES)
    if form.is_valid():
        post = form.save(commit=False)
        post.author = request.user
        post.save()
        messages.success(request, "Post added.")
    else:
        messages.error(request, "Failed to add post.")
    return redirect('profile')

@login_required
def add_tutorial(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")
    form = TutorialForm(request.POST, request.FILES)
    if form.is_valid():
        tut = form.save(commit=False)
        tut.author = request.user
        tut.save()
        messages.success(request, "Tutorial added.")
    else:
        messages.error(request, "Failed to add tutorial.")
    return redirect('profile')

@login_required
def take_snapshot(request):
    """
    Trigger on-demand analysis: fetch CF submissions, analyze, save a WeaknessSnapshot.
    Returns JSON (success + snapshot id).
    """
    handle = request.user.username
    try:
        subs = get_user_submissions(handle)
        tag_scores, avg_rating, solved = analyze_user_submissions(subs)
        # store as dict tag->score
        tag_scores_dict = {t: score for t, score in tag_scores}
        avg_weak = round(sum(tag_scores_dict.values()) / len(tag_scores_dict), 4) if tag_scores_dict else 0.0

        snap = WeaknessSnapshot.objects.create(
            user=request.user,
            tag_scores=tag_scores_dict,
            avg_weakness=avg_weak,
            rating=avg_rating
        )
        return JsonResponse({"ok": True, "snapshot_id": snap.id})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)




# -----------------------------
# Utility: Safe JSON request
# -----------------------------
from collections import defaultdict, Counter
import requests
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# -----------------------------
# Safe JSON fetch
# -----------------------------
# put this near top of your views.py or in core/cf_helpers.py and import it
import requests
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict, Counter
from django.core.cache import cache
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
import logging

logger = logging.getLogger(__name__)

# --------- CONFIG ----------
TIMEOUT = 3                 # short timeout for Railway-friendly requests
RETRIES = 2                 # number of retries for transient failures
BACKOFF_FACTOR = 0.3
MAX_CONTESTS_ANALYZE = 20   # keep it small to avoid long processing
PROBLEM_CACHE_TTL = 24 * 3600
CONTEST_CACHE_TTL = 60 * 60
ANALYSIS_CACHE_TTL = 6 * 3600

# --------- SESSION WITH RETRIES ----------
_session = None


def get_session():
    global _session
    if _session is None:
        s = requests.Session()
        retry = Retry(
            total=RETRIES,
            read=RETRIES,
            connect=RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(['GET', 'POST'])
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _session = s
    return _session


# -----------------------------
# SAFE GET JSON (Railway safe)
# -----------------------------
def safe_get_json(url, timeout=TIMEOUT):
    """
    Returns parsed JSON dict on success, or None on failure.
    Does not raise; logs errors so Railway shows the reason.
    """
    try:
        s = get_session()
        resp = s.get(url, timeout=timeout)
        resp.raise_for_status()

        # parse json
        try:
            data = resp.json()
        except ValueError:
            logger.warning("JSON decode failed for URL: %s", url)
            return None

        # Codeforces uses {status: "OK", result: ...}
        # but other endpoints might behave differently; we return the whole dict
        return data

    except requests.exceptions.RequestException as e:
        logger.warning("Request failed for URL: %s error: %s", url, e)
        return None
    except Exception as e:
        # Catch-all so view never crashes here
        logger.exception("Unexpected error fetching URL %s : %s", url, e)
        return None


# -----------------------------
# Fetch all contests (cached)
# -----------------------------
def get_contests():
    key = "cf_contests_v1"
    contests = cache.get(key)
    if contests is not None:
        return contests

    url = "https://codeforces.com/api/contest.list?gym=false"
    data = safe_get_json(url)
    if not data:
        return []
    # Defensive: expect dict with status/result fields
    if isinstance(data, dict) and data.get("status") == "OK" and "result" in data:
        contests = data["result"]
    elif isinstance(data, list):
        # fallback if some unexpected shape
        contests = data
    else:
        return []

    cache.set(key, contests, timeout=CONTEST_CACHE_TTL)
    return contests


# -----------------------------
# Analyze past contests for tags & ratings
# -----------------------------
def analyze_past_contests(contests, contest_type, max_contests=MAX_CONTESTS_ANALYZE):
    key = f"cf_analysis_{contest_type}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    tag_stats = defaultdict(Counter)
    rating_stats = defaultdict(list)
    counted = 0

    # iterate contests (they are typically sorted by start time descending)
    for contest in contests:
        if counted >= max_contests:
            break

        name = contest.get("name", "")
        phase = contest.get("phase")
        if not name or contest_type not in name:
            continue
        if phase != "FINISHED":
            continue

        cid = contest.get("id")
        if cid is None:
            continue

        standings_url = f"https://codeforces.com/api/contest.standings?contestId={cid}&from=1&count=1"
        data = safe_get_json(standings_url)
        if not data or not isinstance(data, dict) or data.get("status") != "OK":
            # skip contests we couldn't fetch
            logger.info("Skipping contest %s (id=%s) due to missing standings", name, cid)
            continue

        problems = data.get("result", {}).get("problems", []) or []
        for p in problems:
            try:
                idx = p.get("index")
                if not idx:
                    continue
                # use first char as index label (A/B/C) if they are like "A", "B"
                idx_label = idx[0] if isinstance(idx, str) and len(idx) > 0 else idx
                for tag in p.get("tags", []) or []:
                    tag_stats[idx_label][tag] += 1
                if "rating" in p and isinstance(p["rating"], int):
                    rating_stats[idx_label].append(p["rating"])
            except Exception as e:
                logger.warning("Problem processing failed for contest %s id=%s : %s", name, cid, e)
                continue

        counted += 1

    # build percentages and avg ratings
    percentages = {}
    for idx, counter in tag_stats.items():
        total = sum(counter.values()) or 1
        percentages[idx] = {tag: round(cnt * 100.0 / total, 2) for tag, cnt in counter.items()}

    avg_ratings = {}
    for idx, ratings in rating_stats.items():
        if ratings:
            avg_ratings[idx] = round(sum(ratings) / len(ratings))
    result = (percentages, avg_ratings)
    cache.set(key, result, timeout=ANALYSIS_CACHE_TTL)
    return result


# -----------------------------
# Fetch problems by tag & rating, skipping solved (cached)
# -----------------------------
def fetch_problems(tag, rating, solved_set=None, limit=5):
    # Use cache keyed by tag+rating so we don't fetch problemset repeatedly
    key = f"cf_problems_{tag}_{rating}"
    problems = cache.get(key)
    if problems is not None:
        # Filter solved_set again here to be safe (cache contains unsolved candidates)
       if solved_set:
          filtered = [p for p in problems if f"{p['contestId']}/{p['index']}" not in solved_set]
          return filtered[:limit]

       return problems[:limit]


    url = "https://codeforces.com/api/problemset.problems"
    data = safe_get_json(url)
    problems = []
    if not data or not isinstance(data, dict) or "result" not in data:
        cache.set(key, problems, timeout=PROBLEM_CACHE_TTL)
        return problems

    all_problems = data["result"].get("problems", []) or []

    for p in all_problems:
        try:
            # require rating and tag match
            if "rating" not in p:
                continue
            if tag not in (p.get("tags") or []):
                continue
            # only accept rating within +/-200 of requested rating to keep relevant
            if rating and abs(int(p.get("rating", 0)) - int(rating)) > 200:
                continue

            prob_id = f"{p['contestId']}/{p['index']}"

            if solved_set and prob_id in solved_set:
                continue

            problems.append({
                "name": p.get("name"),
                "link": f"https://codeforces.com/contest/{p['contestId']}/problem/{p['index']}",

                "rating": p.get("rating"),
                "tags": p.get("tags", []),
                "contestId": p.get("contestId"),
                "index": p.get("index"),
            })
        except Exception as e:
            # keep going on malformed problem entries
            logger.debug("Skipping malformed problem entry: %s", e)
            continue

        if len(problems) >= limit:
            break

    cache.set(key, problems, timeout=PROBLEM_CACHE_TTL)
    return problems


# -----------------------------
# Helper to get solved IDs from submissions (safe)
# -----------------------------
def get_solved_problem_ids(submissions):
    solved = set()
    if not submissions:
        return solved

    for sub in submissions:
        try:
            if sub.get('verdict') == 'OK' and 'problem' in sub:
                prob = sub['problem']
                solved.add(f"{prob.get('contestId')}/{prob.get('index')}")
        except Exception:
            continue

    return solved



# -----------------------------
# Main view: Contest preparation (safe)
# -----------------------------
@login_required
def conprep_page(request):
    # get contests (cached)
    contests = get_contests() or []
    handle = getattr(request.user, 'username', None) or ""
    # safe retrieval of submissions - your get_user_submissions should be defensive too
    try:
        submissions = get_user_submissions(handle) if handle else []
    except Exception as e:
        logger.warning("Failed to fetch submissions for %s: %s", handle, e)
        submissions = []

    solved_set = get_solved_problem_ids(submissions)

    # Upcoming contests
    upcoming = [c for c in contests if c.get("phase") == "BEFORE"]
    upcoming = sorted(upcoming, key=lambda x: x.get("startTimeSeconds", 0))
    next_contest = upcoming[0] if upcoming else None

    prep_data = {}
    if next_contest:
        name = next_contest.get("name", "") or ""
        # Determine contest type
        if "Div. 2" in name:
            contest_type = "Div. 2"
        elif "Div. 3" in name:
            contest_type = "Div. 3"
        elif "Educational" in name:
            contest_type = "Educational"
        elif "Div. 1" in name:
            contest_type = "Div. 1"
        elif "Div. 4" in name:
            contest_type = "Div. 4"
        else:
            contest_type = "Global"

        # Analyze past contests (cached)
        try:
            percentages, avg_ratings = analyze_past_contests(contests, contest_type)
        except Exception as e:
            logger.exception("analyze_past_contests failed: %s", e)
            percentages, avg_ratings = {}, {}

        # Prepare problems by index (limited)
        for idx, tag_data in (percentages or {}).items():
            try:
                prep_data[idx] = {
                    "tags": tag_data,
                    "avg_rating": int(avg_ratings.get(idx, 1200)),
                    "problems": []
                }
            except Exception:
                prep_data[idx] = {
                    "tags": tag_data,
                    "avg_rating": 1200,
                    "problems": []
                }

            top_tags = sorted(tag_data.items(), key=lambda x: -x[1])[:2]
            for tag, _ in top_tags:
                rating = avg_ratings.get(idx, 1200)
                try:
                    problems = fetch_problems(tag, rating, solved_set=solved_set, limit=5)
                except Exception as e:
                    logger.warning("fetch_problems failed for tag=%s rating=%s : %s", tag, rating, e)
                    problems = []
                prep_data[idx]["problems"].extend(problems)

    # render safely even if some parts failed
    return render(request, "contest_prep.html", {
        "upcoming": upcoming[:5],
        "next_contest": next_contest,
        "prep_data": prep_data
    })
