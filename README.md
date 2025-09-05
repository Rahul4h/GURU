# 🤖 GURU – Codeforces Training Assistant

**GURU** is a **Django  web app** that integrates with **Codeforces** to help competitive programmers improve their problem-solving skills.  
It analyzes a user’s Codeforces profile, generates rating charts, and provides **personalized problem suggestions** based on weak topics and performance trends.  

---

## 🚀 Features

- 🔑 **User Authentication**
  - Google OAuth login (via `django-allauth`)
  - Secure signup / login / logout
  - Index page restricted to logged-in users only

- 📊 **Codeforces Profile Integration**
  - Import Codeforces handle
  - Fetch user rating history
  - Visualize rating progress (line charts, graphs)
  - Compare ratings in leaderboard view

- 🎯 ** Suggestions**
  - Analyze solved vs. unsolved problems
  - Suggest weak → strong tags per rating range
  - Recommend problems in 4 difficulty bands:
    - 800–1100
    - 1200–1400
    - 1500–1600
    - 1600–1900
  - Direct links to Codeforces problems

- 📝 **Suggestions Page**
  - Organized UI showing tags & problems per rating band
  - Clickable sections for detailed recommendations

- 📈 **Leaderboard**
  - Compare performance with previous performance of that users
  - Track ratings and problem counts

---

## 🏗️ Tech Stack

- **Backend:** Django, Django ORM  
- **Frontend:** HTML, CSS, Bootstrap, Chart.js  
- **Database:** SQLite (recommended: PostgreSQL for production)  
- **Authentication:** Google OAuth (via `django-allauth`)  
- **Machine Learning:** scikit-learn / pandas / numpy  
- **API Integration:** Codeforces API  

---

---

## ⚙️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/GURU.git
   cd GURU
2.Create a virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
3.Run migrations
python manage.py migrate

4.Set up Google OAuth

Create a project in Google Cloud Console

Enable OAuth credentials for http://127.0.0.1:8000/

Add client ID & secret in Django settings (settings.py)

5.Run the server
python manage.py runserver

👨‍💻 Author

Rahul Ghosh
💼 Django & FastAPI Developer

