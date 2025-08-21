

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

@login_required
def blog_page(request):
    posts = Post.objects.all().order_by('-created_at')
    return render(request, 'blog.html', {'posts': posts})


# app/views.py





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

def get_ml_suggestions(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            handle = data.get('handle')

            # 👉 Example: Simulate ML logic (replace with your real model)
            problem_suggestions = [
                {
                    "title": "Helpful Maths",
                    "tags": ["implementation"],
                    "rating": 800,
                    "url": "https://codeforces.com/problemset/problem/339/A"
                },
                {
                    "title": "Way Too Long Words",
                    "tags": ["strings"],
                    "rating": 800,
                    "url": "https://codeforces.com/problemset/problem/71/A"
                },
                {
                    "title": "Next Round",
                    "tags": ["implementation"],
                    "rating": 800,
                    "url": "https://codeforces.com/problemset/problem/158/A"
                }
            ]

            return JsonResponse({'suggestions': problem_suggestions})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

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


from django.contrib import messages
from django.contrib.auth.models import User
from django.db import transaction, IntegrityError
from django.shortcuts import redirect, render
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator


def handlesignup(request):
    if request.method == "POST":
        uname = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip().lower()
        password = request.POST.get("pass1")
        confirmpassword = request.POST.get("pass2")

        # 1. Empty field check
        if not uname or not email or not password or not confirmpassword:
            messages.error(request, "All fields are required.")
            return redirect('handlesignup')

        # 2. Password match
        if password != confirmpassword:
            messages.warning(request, "Passwords do not match.")
            return redirect('handlesignup')

        # 3. Username check
        existing_username = User.objects.filter(username__iexact=uname).first()
        if existing_username:
            if not existing_username.is_active:
                _send_activation_email(request, existing_username)
                messages.info(request, "Inactive account exists. Activation email resent.")
                return redirect('handlelogin')
            messages.info(request, "Username is already taken.")
            return redirect('handlesignup')

        # 4. Email check
        existing_email = User.objects.filter(email__iexact=email).first()
        if existing_email:
            if not existing_email.is_active:
                _send_activation_email(request, existing_email)
                messages.info(request, "Inactive account exists. Activation email resent.")
                return redirect('handlelogin')
            messages.info(request, "Email already registered.")
            return redirect('handlesignup')

        # 5. Create user and send activation
        try:
            with transaction.atomic():
                user = User.objects.create_user(username=uname, email=email, password=password)
                user.is_active = False
                user.save()

                _send_activation_email(request, user)

            messages.success(request, "Account created. Check your email for activation link.")
            return redirect('handlelogin')

        except IntegrityError:
            messages.error(request, "User with this username or email already exists.")
            return redirect('handlesignup')

    return render(request, 'signup.html')


from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site

def _send_activation_email(request, user):
    current_site = get_current_site(request)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    message = render_to_string('activate_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uidb64': uidb64,
        'token': token,
    })

    email = EmailMessage(
        subject='Activate your account',
        body=message,
        to=[user.email],
    )
    email.content_subtype = 'html'
    email.send()



from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.models import User

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been activated! You can now log in.")
        return redirect('handlelogin')
    else:
        messages.error(request, "Activation link is invalid or has expired.")
        return redirect('handlesignup')



    


def handlelogin(request):
    if request.method=="POST":
        uname=request.POST.get("username")
        pass1=request.POST.get("pass1")
        myuser=authenticate(username=uname,password=pass1)
        if myuser is not None:
            login(request,myuser)
            messages.success(request,"login success")
            return redirect('/')
        else:
            messages.error(request,"invalid")
            return redirect('/login')
    return render(request,'login.html')

def handlelogout(request):
    logout(request)
    messages.info(request,"logout success")
    return redirect('/login')



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
