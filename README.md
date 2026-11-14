# SentinelMail

### AI-Powered Email Phishing Detection & Threat Analysis Platform

SentinelMail is a machine learning-powered web application designed to identify phishing emails and analyze potential email-based cybersecurity threats. It combines machine learning classification with rule-based security analysis to provide users with insights into suspicious email content.

## Features

- **AI-Based Phishing Detection:** Classifies emails as Phishing or Legitimate using a machine learning model.
- **Threat Scoring:** Calculates an overall threat score and assigns a threat severity level.
- **URL Analysis:** Identifies suspicious URLs and potentially malicious domains.
- **Keyword Analysis:** Detects suspicious language, urgency, and credential-related requests.
- **Email Header Analysis:** Evaluates SPF, DKIM, DMARC, and Reply-To information.
- **Sender Analysis:** Examines sender information for suspicious characteristics.
- **Email Scanning:** Supports analyzing pasted email content and uploaded `.eml` files.
- **Scan History:** Maintains records of previously analyzed emails.
- **User Authentication:** Provides registration, login, and password management.
- **Dashboard:** Displays scan statistics and analysis results.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Machine Learning | Scikit-learn |
| NLP | TF-IDF Vectorization |
| ML Algorithm | Logistic Regression |
| Database | SQLite / PostgreSQL |
| ORM | Flask-SQLAlchemy |
| Frontend | HTML, CSS, JavaScript, Bootstrap |
| Security Analysis | Python-based analysis modules |

## Machine Learning

The phishing detection model uses TF-IDF feature extraction and Logistic Regression to classify email content.

The model was trained using a phishing and legitimate email dataset.

## Project Structure

```text
SentinelMail/
├── ai/
│   ├── model.pkl
│   ├── vectorizer.pkl
│   ├── predictor.py
│   └── train_model.py
├── app/
│   ├── models.py
│   ├── route.py
│   ├── auth.py
│   ├── templates/
│   └── static/
├── cybersecurity/
│   ├── url_checker.py
│   ├── keyword_checker.py
│   ├── header_checker.py
│   ├── sender_checker.py
│   └── threat_score.py
├── dataset/
├── reports/
├── requirements.txt
└── sentinelmail.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Sadaf-02/SentinelMail.git
cd SentinelMail
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

Windows:
```powershell
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file and configure the required application settings:

- `SECRET_KEY`
- `DATABASE_URL`
- `MAIL_SERVER`
- `MAIL_PORT`
- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `MAIL_DEFAULT_SENDER`

### 5. Run the application

```bash
python sentinelmail.py
```

Open the local application in your browser at:

`http://127.0.0.1:5000`

## Future Enhancements

- Integration with additional threat intelligence sources
- Advanced email attachment analysis
- Improved phishing detection and model evaluation
- Deployment on a cloud hosting platform
- Enhanced security reporting and visualization

## Disclaimer

SentinelMail is an educational cybersecurity project. Its predictions and threat scores should be treated as indicators rather than definitive proof that an email is malicious or safe.