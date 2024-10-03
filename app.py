from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
import bcrypt
import hashlib
import rsa
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'electionSecret'

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='12345678',
        database='online_voting'
    )

(public_key, private_key) = rsa.newkeys(512)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_vote(vote_data):
    return rsa.encrypt(vote_data.encode(), public_key)

def decrypt_vote(encrypted_data):
    return rsa.decrypt(encrypted_data, private_key).decode()

@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('voter_logged_in', None)
    session.pop('admin_logged_in', None)
    return redirect(url_for('index')) 


@app.route('/voter_signup', methods=['GET', 'POST'])
def voter_signup():
    if request.method == 'POST':
        data = request.get_json()
        aadhaar = data.get('aadhaar')
        password = data.get('password')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db_connection()
        cur = db.cursor()
        try:
            cur.execute("INSERT INTO voters (voter_id, aadhaar_number, password) VALUES (UUID(), %s, %s)", (aadhaar, hashed_password))
            db.commit()  

            return jsonify({'success': True, 'message': 'Signup successful! You can now login.'})
        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': f'Error occurred: {str(e)}'})
        finally:
            cur.close() 

    return render_template('voter_signup.html')



@app.route('/voter_login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        data = request.get_json()
        aadhaar = data.get('aadhaar')
        password = data.get('password')

        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT voter_id, aadhaar_number, password FROM voters WHERE aadhaar_number=%s", (aadhaar,))
        voter = cur.fetchone()
        cur.close()

        if voter and bcrypt.checkpw(password.encode('utf-8'), voter[2].encode('utf-8')):  # Assuming password is stored hashed
            session['voter_logged_in'] = True
            session['voter_id'] = voter[0] 
            session['aadhaar_number'] = aadhaar
            return jsonify({'success': True, 'redirect_url': url_for('voter_dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid Aadhaar number or password'})

    return render_template('voter_login.html')




@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM admins WHERE username=%s", (username,))
        admin = cur.fetchone()
        cur.close()
        if admin and password == admin[2]: 
            session['admin_logged_in'] = True
            return jsonify({'success': True, 'redirect_url': url_for('admin_dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'})

    return render_template('admin_login.html')



@app.route('/voter_dashboard')
def voter_dashboard():
    if 'voter_logged_in' in session:
        db = get_db_connection()
        cur = db.cursor()

        cur.execute("SELECT * FROM elections WHERE CAST(start_time AS DATETIME) <= NOW() AND CAST(end_time AS DATETIME) >= NOW();")
        active_election = cur.fetchone()
        print(active_election)
        cur.close()
        db.close()

        if active_election:
            return render_template('voter_dashboard.html', active_election=active_election)
        else:
            message = 'No election is currently scheduled'
            return render_template('voter_dashboard.html', message=message)
    return redirect(url_for('voter_login'))

@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
def vote(election_id):
    if 'voter_logged_in' in session:
        voter_id = session['voter_id']

        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM votes WHERE voter_id=%s AND election_id=%s", (voter_id, election_id))
        existing_vote = cur.fetchone()
        
        if existing_vote:
            flash('You have already voted in this election.', 'danger')
            return redirect(url_for('voter_dashboard'))

        if request.method == 'POST':
            candidate_id = request.form['candidate_id']
            encrypted_vote = encrypt_vote(f'{voter_id}:{election_id}:{candidate_id}')  
            
            cur.execute("INSERT INTO votes (voter_id, election_id, candidate_id, encrypted_vote) VALUES (%s, %s, %s, %s)",
                        (voter_id, election_id, candidate_id, encrypted_vote))
            db.commit()
            cur.close()
            db.close()

            flash('Your vote has been cast successfully!', 'success')
            return redirect(url_for('voter_dashboard'))

        cur.execute("SELECT * FROM candidates WHERE election_id=%s", [election_id])
        candidates = cur.fetchall()
        cur.close()
        db.close()
        
        return render_template('vote.html', candidates=candidates)

    return redirect(url_for('voter_login'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' in session:
        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT id, election_name FROM elections")
        elections = cur.fetchall()
        cur.close()
        db.close()

        return render_template('admin_dashboard.html', elections=elections)
    return redirect(url_for('admin_login'))


@app.route('/manage_candidates', methods=['GET', 'POST'])
def manage_candidates():
    if 'admin_logged_in' in session:
        if request.method == 'POST':
            name = request.form['name']
            details = request.form['details']
            election_id = request.form['election_id']
            
            db = get_db_connection()
            cur = db.cursor()
            cur.execute("INSERT INTO candidates (name, details, election_id) VALUES (%s, %s, %s)", (name, details, election_id))
            db.commit()
            cur.close()
            db.close()
            
            flash('Candidate added successfully!', 'success')

        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM candidates")
        candidates = cur.fetchall()
        cur.close()
        db.close()

        return render_template('manage_candidates.html', candidates=candidates)

    return redirect(url_for('admin_login'))

@app.route('/schedule_election', methods=['GET', 'POST'])
def schedule_election():
    if 'admin_logged_in' in session:
        if request.method == 'POST':
            election_name = request.form['election_name']
            start_time = request.form['start_time']
            end_time = request.form['end_time']

            db = get_db_connection()
            cur = db.cursor()
            cur.execute("INSERT INTO elections (election_name, start_time, end_time) VALUES (%s, %s, %s)", (election_name, start_time, end_time))
            db.commit()
            cur.close()
            db.close()

            flash('Election scheduled successfully!', 'success')

        return render_template('schedule_election.html')

    return redirect(url_for('admin_login'))

@app.route('/view_results/<int:election_id>')
def view_results(election_id):
    if 'admin_logged_in' in session:
        db = get_db_connection()
        cur = db.cursor()
        
        cur.execute("SELECT end_time FROM elections WHERE id=%s", (election_id,))
        election = cur.fetchone()
        if not election:
            flash("Election not found.", 'danger')
            return redirect(url_for('admin_dashboard'))

        end_time = election[0]

        from datetime import datetime
        current_time = datetime.now()
        if current_time < end_time:
            flash("Election is still ongoing. Results will be available after the election concludes.", 'warning')
            return render_template('view_results.html', message="Election ongoing.")
        
        cur.execute("""
            SELECT candidates.name, COUNT(votes.candidate_id) as vote_count 
            FROM votes 
            JOIN candidates ON votes.candidate_id = candidates.id 
            WHERE votes.election_id=%s 
            GROUP BY candidates.name
            ORDER BY vote_count DESC
        """, [election_id])
        results = cur.fetchall()
        cur.close()
        db.close()

        return render_template('view_results.html', results=dict(results))
    return redirect(url_for('admin_login'))


@app.route('/delete_candidate/<int:candidate_id>', methods=['POST'])
def delete_candidate(candidate_id):
    if 'admin_logged_in' in session:
        db = get_db_connection()
        cur = db.cursor()
        cur.execute("DELETE FROM votes WHERE candidate_id = %s", (candidate_id,))
        db.commit()
        cur.execute("DELETE FROM candidates WHERE id = %s", (candidate_id,))
        db.commit()
        cur.close()
        db.close()
        return jsonify({'success': True, 'message': 'Candidate and related votes deleted successfully!'})
    return jsonify({'success': False, 'message': 'You need to be logged in as admin.'})



if __name__ == '__main__':
    app.run(debug=True)
