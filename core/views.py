
from django.shortcuts import render,redirect
from django.http import JsonResponse
import json
import requests
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages





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


def recommend_problems(tag_scores, avg_rating, problems, solved_problems, max_per_tag=20):
    """
    Returns a prioritized list of unsolved problems based on weakest tags and difficulty.
    The frontend can page through this list (e.g., show first 10, then next 10, etc.)
    """
    tag_scores = sorted(tag_scores, key=lambda x: x[1], reverse=True)  # Weakest tags first
    recommendations = []
    used_ids = set()

    difficulty_buckets = [
        (avg_rating - 200, avg_rating - 100, 2),
        (avg_rating - 0, avg_rating + 0, 3),
        (avg_rating + 100, avg_rating + 200, 3),
        (avg_rating + 300, avg_rating + 400, 2)
    ]

    for tag, _ in tag_scores:
        tag_problems = []
        for lower, upper, _ in difficulty_buckets:
            for prob in problems:
                tags = prob.get('tags', [])
                rating = prob.get('rating', 0)
                prob_id = f"{prob['contestId']}/{prob['index']}"

                if prob_id in solved_problems or prob_id in used_ids:
                    continue

                if tag not in tags:
                    continue

                if lower <= rating <= upper:
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
            if len(tag_problems) >= max_per_tag:
                break

        recommendations.extend(tag_problems)

    return recommendations


from django.http import JsonResponse
import json
@csrf_exempt
def ml_suggestions_view(request):
    if request.method == 'POST':
        body = json.loads(request.body)
        handle = body.get('handle')

        submissions = get_user_submissions(handle)
        tag_scores, avg_rating, solved_problems = analyze_user(submissions)
        problems = get_problemset()
        recs = recommend_problems(tag_scores, avg_rating, problems, solved_problems)
        tag_strengths = [{'tag': tag, 'score': score} for tag, score in tag_scores]


        return JsonResponse({'suggestions': recs,
                             'tag_strengths': tag_strengths
                             })

    
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator

def handlesignup(request):
    if request.method == "POST":
        uname = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("pass1")
        confirmpassword = request.POST.get("pass2")

        # Basic empty check
        if not uname or not email or not password or not confirmpassword:
            messages.error(request, "All fields are required.")
            return redirect('handlesignup')

        if password != confirmpassword:
            messages.warning(request, "Passwords do not match")
            return redirect('handlesignup')

        if User.objects.filter(username=uname,is_active=True).exists():
            messages.info(request, "Username is already taken")
            return redirect('handlesignup')

        if User.objects.filter(email=email,is_active=True).exists():
            messages.info(request, "Email is already registered")
            return redirect('handlesignup')

        # Create inactive user
        user = User.objects.create_user(username=uname, email=email, password=password)
        user.is_active = False
        user.save()

        # Send activation email
        current_site = get_current_site(request)
        subject = "Activate Your HAT Account"
        message = render_to_string('activate_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user),
        })

        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            messages.success(request, "Please check your email to activate your account.")
        except Exception as e:
            messages.error(request, "Error sending activation email. Please try again.")
            user.delete()  # Clean up created user
            return redirect('handlesignup')

        return redirect('handlelogin')
    
    return render(request, 'signup.html')

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







