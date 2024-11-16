import sqlite3

conn = sqlite3.connect('./databases/profiles.db')

cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS profile (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        github_link TEXT,
        linkedin_link TEXT,
        resume_pdf BLOB,
        unique_number INTEGER UNIQUE,
        domain_score REAL,
        resume_score REAL,
        shortlisted_hackathons TEXT
    )
''')

conn.commit()

def add_profile(first_name, last_name, github_link, linkedin_link, resume_pdf_path, unique_number, domain_score, resume_score, shortlisted_hackathons):
    with open(resume_pdf_path, 'rb') as file:
        resume_pdf = file.read()

    cursor.execute('''
        INSERT INTO profile (first_name, last_name, github_link, linkedin_link, resume_pdf, unique_number, domain_score, resume_score, shortlisted_hackathons)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, github_link, linkedin_link, resume_pdf, str(unique_number), str(domain_score), str(resume_score), str(shortlisted_hackathons)))

    conn.commit()

def fetch_profile_by_unique_number(unique_number):
    cursor.execute('SELECT * FROM profile WHERE unique_number = ?', (unique_number,))
    return cursor.fetchone()

# Example usage
if __name__ == '__main__':

    add_profile('John', 'Doe', 'https://github.com/johndoe', 'https://linkedin.com/in/johndoe', './demopdfs/resume.pdf', 
                unique_number=12345, domain_score=[85.5], resume_score=90.0, shortlisted_hackathons='[Hackathon A, Hackathon B]')

    unique_number_to_fetch = 12345
    profile = fetch_profile_by_unique_number(unique_number_to_fetch)
    print(profile)
