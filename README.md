# GURU Project

GURU is a Django + ML project for Codeforces problem suggestions.

## Features
- Google OAuth login
- Leaderboard and rating graphs
-  problem suggestions
- Suggestions by rating ranges: 800–1100, 1200–1400, 1500–1600, 1600–1900
- Show weakness score for each tag in suggestion
- Show weakness graph (lower==better)
-  profile has options for blog post ,user can comment ,reply and react(like,dislike,love)
- User can write tutorial and read tutorials from expert users.


## Setup
1. Create a virtual environment: `python -m venv venv`
2. Install requirements: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Start server: `python manage.py runserver`
