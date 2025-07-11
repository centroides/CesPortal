from flask import Flask, render_template, request, redirect, url_for, Response,flash,send_file, session,jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, url_for, request, session, g
from flask.templating import render_template
from mpl_toolkits.mplot3d import Axes3D
from datetime import datetime, timedelta                                                                                                                                                                                                                                                                                                                                                    
from werkzeug.utils import redirect
from database import get_database
from flask import make_response
from flask_mail import Mail, Message
import random
from matplotlib import animation
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from functools import wraps
import pandas as pd
import numpy as np
import copy
import datetime
import base64
import sqlite3
import os
import io
import smtplib
import shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import locale
import re
from io import BytesIO
from fpdf import FPDF
import calendar

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
mail=Mail(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'cestimesheet67@gmail.com'
app.config['MAIL_PASSWORD'] = 'tzrsaxvfcbzuekon'
app.config['MAIL_DEBUG'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'cestimesheet67@gmail.com'

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Store OTP in session
def store_otp_in_session(otp):
    session['otp'] = otp

# Verify OTP
def verify_otp(entered_otp):
    return 'otp' in session and session['otp'] == entered_otp

def get_employee_access_control(employee_id):

    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM access_control WHERE Employee_ID = ?', (employee_id,))
    row = cursor.fetchone()
    db.commit()
    
    query = "SELECT * FROM access_control WHERE Employee_ID = ?"
    cursor.execute(query, (employee_id,))
    row = cursor.fetchone()
    
    if row:
        columns = [desc[0] for desc in cursor.description]
        access_controls = dict(zip(columns, row))
        return access_controls
    else:
        return None

@app.route('/register', methods=["POST", "GET"])
def register():
    user = get_current_user()
    db = get_database()

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        # Check if the user with the same username (email) exists in the users table
        dbuser_cur = db.execute('SELECT * FROM users WHERE name = ?', [email])
        existing_username = dbuser_cur.fetchone()
        # Check if the user has register value equal to 1 in the admin_user table
        admin_user_cur = db.execute('SELECT * FROM admin_user WHERE name = ? AND register = 1', [email])
        admin_user = admin_user_cur.fetchone()
        get_name = db.execute('SELECT username FROM admin_user WHERE name = ?', (email,))
        name_to_user_table = get_name.fetchone()[0]
        if existing_username or not admin_user:
            return render_template('login.html', registererror='You are not authorized to register.')

        # Insert the new user into the users table
        db.execute('INSERT INTO users(name, password) VALUES (?, ?)', [name_to_user_table, hashed_password])
        db.commit()
        return redirect(url_for('index'))

    return render_template('login.html', user=user)

@app.route('/login', methods=['POST', 'GET'])
def login():
    user = get_current_user()
    error = None
    db = get_database()
    if request.method == 'POST':
        session['logged_in'] = True
        name = request.form['name']
        password = request.form['password']
        admin_user_cur = db.execute('SELECT * FROM admin_user WHERE (name = ? OR username = ?) AND register = 1', [name, name])
        dbuser_cur = db.execute('SELECT * FROM admin_user WHERE (name = ? OR username = ?)', [name,name])
        existing_username = dbuser_cur.fetchone()
        admin_level_check = admin_user_cur.fetchone()
        if not admin_level_check:
            return render_template('login.html', registererror='You are not authorized to register.....!')

        user_cursor = db.execute('SELECT * FROM users WHERE (email =? or name = ?)', [name,name])
        user = user_cursor.fetchone()
        if user:
            
            if check_password_hash(user['password'], password):
                session['user'] = user['name']
                from datetime import datetime
                session['last_activity'] = datetime.now().timestamp()  # Store current timestamp
                department_code = get_department_code_by_username( user['name'])
                from datetime import datetime
                db.execute("INSERT INTO user_history (username, action, timestamp) VALUES (?, ?, ?)",
                    (user['name'], "Logged in successfully", datetime.now()) ) 
                db.commit()
                if department_code == 1025:
                    return redirect(url_for('accounts'))
                return redirect(url_for('profile'))
                pmstat  = get_pm_status(user['name'])
                pestat  = get_pe_status(user['name'])
                otp = generate_otp()
                store_otp_in_session(otp)
                if not existing_username:
                    return render_template('login.html', registererror='Your Email is not register with us .....!')
                else:
                    send_otp_email(user['email'], otp)
                    return render_template('verify_otp_page.html',mail = user['email'])
                # return render_template('admin_templates/admin/index.html')
                return redirect(url_for('projects'))
            else:
                error = "Username or Password did not match. Please try again."
        else:
            error = "Username or Password did not match. Please try again."
    username_suggestions = get_username_suggestions()
    return render_template('login.html', loginerror = error, user = user, username_suggestions = username_suggestions)

from datetime import datetime
from flask import session, redirect, url_for
import sqlite3

@app.before_request
def check_inactivity():
    if 'user' in session:
        from datetime import datetime
        now = datetime.now().timestamp()
        last_activity = session.get('last_activity', now)
        timeout_seconds = 20 * 60  # 10 minutes in seconds
        if now - last_activity > timeout_seconds:
            username = session.get('user')  # Get the username from the session
            db = get_database()  # Replace this with your actual database connection method
            from datetime import datetime
            db.execute("INSERT INTO user_history (username, action, timestamp) VALUES (?, ?, ?)", (username, "Logged out due to inactivity", datetime.now()) ) 
            db.commit()
            session.pop('user', None)
            session.pop('last_activity', None)
            return redirect(url_for('login'))
        session['last_activity'] = now  # Update last activity timestamp

def send_otp_email(receiver_email, otp):
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")
    subject = "From Centroid Engineering Solutions"
    body = f"Your OTP is: '{otp}'. This OTP is valid for a short period. Do not share it with anyone."
    message = MIMEMultipart()
    message['From'] = "cestimesheet67@gmail.com"
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    s.sendmail("cestimesheet67@gmail.com", receiver_email, message.as_string())
    print('OTP email sent successfully.')
    s.quit()

@app.route('/verify_otp', methods=['POST', 'GET'])
def verify_otp_page():
    error = None
    if request.method == 'POST':
        entered_otp = ''.join(request.form.getlist('otp[]'))
        option = request.form['option']
        email = request.form[ 'mail']
        if option:
            if verify_otp(entered_otp):
                return render_template('forgot_password.html', mail=email,option = option)
            else:
                flash(f"Invalid OTP. Please try again.", 'error')
                return render_template('verify_otp_page.html',   mail=email,option = option,registererror='Invalid OTP .....!')
        # Verify OTP
        if verify_otp(entered_otp):
            return redirect(url_for('projects'))
        else:
            flash(f"Invalid OTP. Please try again.", 'error')
        return render_template('verify_otp_page.html',   mail=email,option = option,registererror='Invalid OTP .....!')

    return render_template('login.html', registererror='Your Email is not register with us .....!')

@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    option = request.args.get('option', default=False, type=lambda v: v.lower() in ('true', '1', 't'))
    print('Option:', option) 
    if request.method == 'POST':
        email = request.form['email']
        # print(".........EMAIL.",email)
        db = get_database()
        user_cursor = db.execute('SELECT * FROM users WHERE email = ?', [email])
        user = user_cursor.fetchone()
        if not user:
            admin_user_cursor = db.execute('SELECT * FROM admin_user WHERE name = ?', [email])
            user = admin_user_cursor.fetchone()
            # print(".............admin_user...........", user)
        # print(".............user...........",user)
        if user:
            otp = generate_otp()
            print("..............otp...",otp)
            store_otp_in_session(otp)
            send_otp_email(email, otp)
            session['reset_email'] = email
            return render_template('verify_otp_page.html', mail=email,option = option)
        else:
            flash('Email not found', 'error')
            return redirect(url_for('forgot_password', option=False))
    return render_template('forgot_password.html', option=option)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('forgot_password', option=True))

    email = session.get('reset_email')
    if not email:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('forgot_password', option=False))

    hashed_password = generate_password_hash(new_password)
    db = get_database()
    user_cursor = db.execute('SELECT * FROM users WHERE email = ?', [email])
    user = user_cursor.fetchone()
    # print('userrrrrrrrrrrrr..............',user)

    if user:
        db.execute('UPDATE users SET password = ? WHERE email = ?', [hashed_password, email])
    else:
        # print("we didn't find ...............")
        admin_user_cursor = db.execute('SELECT * FROM admin_user WHERE name = ?', [email])
        admin_user = admin_user_cursor.fetchone()
        if admin_user:
            username = admin_user['username']
            # print("...........username.................",username)
            db.execute('UPDATE users SET password = ? WHERE name = ?', [hashed_password, username])
        else:
            flash('Email not found', 'error')
            return redirect(url_for('forgot_password', option=True))

    db.commit()
    flash('Password has been reset successfully', 'success')
    return redirect(url_for('login'))

def login_required(f):                                                                                                                  
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_pm_status(pm_name):                                                                                                                                                                                                                             
    # print("we are in get pm status function .......................her eis  pm name.......",pm_name)
    db = get_database()
    result = db.execute('SELECT pm_status FROM projects WHERE pm = ?', [pm_name]).fetchone()
    # print("after selecting from the table status .....................................",result)
    if result is None:
        return 0
    if result:
        return result['pm_status']
    else:
        return 0

def get_pe_status(pe_name):                                                                                                                                                                                                                             
    # print("we are in get pm status function .......................her eis  pm name.......",pm_name)
    db = get_database()
    result = db.execute('SELECT pm_status FROM projects WHERE pe = ?', [pe_name]).fetchone()
    # print("after selecting from the table status .....................................",result)
    if result is None:
        return 0
    if result:
        return result['pm_status']
    else:
        return 0

@app.teardown_appcontext
def close_database(error):
    if hasattr(g, 'centro_db'):
        g.centro_db.close()
 
def get_current_user():
    user = None
    if 'user' in session:
        user = session['user']
        db = get_database()
        user_cur = db.execute('select * from users where name = ?', [user])
        user = user_cur.fetchone()
        # print("get the current user.........................",user)
    return user

def get_username_suggestions():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM admin_user')
        usernames = [row[0] for row in cursor.fetchall()]
    return usernames

def get_department_code_by_username(username):
    db = get_database()
    db.row_factory = sqlite3.Row  
    cursor = db.cursor()
    cursor.execute('SELECT department_code FROM admin_user WHERE username = ?', [username])
    result = cursor.fetchone()
    if result:
        department_code = result['department_code']
    else:
        department_code = None
    return department_code

@app.route('/get_department_code_ts')
def get_department_code_ts():
    # Get the username from the request parameters
    username = request.args.get('username')
    if username:
        db = get_database()
        db.row_factory = sqlite3.Row  
        cursor = db.cursor()
        cursor.execute('SELECT department_code FROM admin_user WHERE username = ?', (username,))
        result = cursor.fetchone()
        print("...employee..department_code...",username,result['department_code'])
        if result:
            # If a result is found, return the department code in JSON format
            return jsonify({'department_code': result['department_code']})
        else:
            # If no result is found, return an error message
            return jsonify({'error': 'Employee not found'}), 404
    else:
        # If no username is provided in the request, return a bad request response
        return jsonify({'error': 'No username provided'}), 400

@app.route('/get_project_details_ts', methods=['GET'])
def get_project_details_ts():
    project_id = request.args.get('project_id')
    
    if project_id:
        db = get_database()
        db.row_factory = sqlite3.Row  
        cursor = db.cursor()
        cursor.execute('SELECT project_name, client FROM projects WHERE id = ?', (project_id,))
        project = cursor.fetchone()
        if project:
            return jsonify({ 'project_name': project['project_name'],'client': project['client'] })
        else:
            return jsonify({'error': 'Project not found'}), 404
    else:
        return jsonify({'error': 'No project ID provided'}), 400

@app.route('/get_enq_details_ts', methods=['GET'])
def get_enq_details_ts():
    enq_id = request.args.get('enq_id')
    
    if enq_id:
        db = get_database()
        db.row_factory = sqlite3.Row  
        cursor = db.cursor()
        cursor.execute('SELECT Name, Client FROM enquiries WHERE EnquiryNumber = ?', (enq_id,))
        enq = cursor.fetchone()
        print("...enq_id..name.........client...",enq_id,enq['Name'],enq['Client'] )

        if enq:
            return jsonify({ 'enq_name': enq['Name'],'enq_client': enq['Client'] })
        else:
            return jsonify({'error': 'Enquary not found'}), 404
    else:
        return jsonify({'error': 'No Enquary ID provided'}), 400

def is_he_pm_by_username(username):
    db = get_database()
    db.row_factory = sqlite3.Row  
    cursor = db.cursor()
    cursor.execute('SELECT COUNT(*) FROM projects WHERE pm = ?', [username])
    result = cursor.fetchone()
    is_pm = result[0] > 0 if result else False
    return is_pm

def is_he_pe_by_username(username):
    db = get_database()
    db.row_factory = sqlite3.Row  
    cursor = db.cursor()
    cursor.execute('SELECT COUNT(*) FROM projects WHERE pe = ?', [username])
    result = cursor.fetchone()
    is_pe = result[0] > 0 if result else False
    return is_pe

def is_pm_for_project(user_name):
    db = get_database()
    cursor = db.cursor()
    query = 'SELECT COUNT(*) FROM projects WHERE pm = ?'
    cursor.execute(query, [user_name])
    result = cursor.fetchone()
    return result[0] > 0 if result else False

def is_pe_for_project(user_name):
    db = get_database()
    cursor = db.cursor()
    query = 'SELECT COUNT(*) FROM projects WHERE pe = ?'
    cursor.execute(query, [user_name])
    result = cursor.fetchone()
    return result[0] > 0 if result else False

def getProjectStatusById(projectid):
    db = get_database()
    db.row_factory = sqlite3.Row  
    cursor = db.cursor()
    cursor.execute('SELECT status FROM projects WHERE id = ?', [projectid])
    result = cursor.fetchone()
    if result:
        status = result['status']
    else:
        status = None
    return status

def get_client_names():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT client FROM projects')
        client_names = [row[0] for row in cursor.fetchall()]
        # print("---------------------------------------", client_names)
    return client_names

def get_enuiry_client_names():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT Client FROM enquiries')
        enquiry_client_names = [row[0] for row in cursor.fetchall()]
    return enquiry_client_names

def get_enuiry_ids():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
        enquiry_ids = [row[0] for row in cursor.fetchall()]
    return enquiry_ids

@app.route('/get_enquiry_client_projname/<int:enquiry_id>', methods=['GET'])
@login_required
def get_enquiry_client_projname(enquiry_id):
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT Client, Name FROM enquiries WHERE EnquiryNumber = ?', (enquiry_id,))
        enquiry = cursor.fetchone()
        if enquiry:
            client = enquiry['Client']
            project_name = enquiry['Name']
            print(client,project_name)
            return jsonify({
                'client': client,
                'project_name': project_name
            })
        else:
            return jsonify({'error': 'Enquiry not found'}), 404

def get_enquiry_project_ids():
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT EnquiryNumber, Client FROM enquiries')
    projects = cursor.fetchall()
    enquiry_project_ids = [{'EnquiryNumber': row[0], 'Client': row[1]} for row in projects]
    return enquiry_project_ids

def get_enquires_project_ids_by_client(client_name):
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT EnquiryNumber, Client FROM enquiries WHERE Client = ?', (client_name,))
    projects = cursor.fetchall()
    enquiry_project_ids = [{'EnquiryNumber': row[0], 'Client': row[1]} for row in projects]
    return enquiry_project_ids

def get_enquries_project_names():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT Name FROM enquiries')
        enquiry_project_name = [row[0] for row in cursor.fetchall()]
    return enquiry_project_name

@app.route('/get_enquiry_project_ids_suggestions/<client>')
def get_enquiry_project_ids_suggestions(client):
    try:
        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT EnquiryNumber FROM enquiries WHERE Client = ?", (client,))
        project_ids = [row[0] for row in cursor.fetchall()]
        return jsonify(project_ids=project_ids)
    except Exception as e:
        return jsonify(project_ids=[]), 500  
    finally:
        cursor.close()
        db.close()

def get_enquiry_project_names():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT Name FROM enquiries')
        project_name = [row[0] for row in cursor.fetchall()]
        # print("..........get_enquiry_project_names",project_name)
    return project_name

def query_database_for_enquiry_project_name(selected_client, selected_enq_project_id):
    # Remove leading and trailing spaces from selected_client
    selected_client = selected_client.strip()
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT Name FROM enquiries WHERE EnquiryNumber = ? AND Client = ?", (selected_enq_project_id, selected_client))
    result = cursor.fetchone()

    if result:
        db.commit()
        return result[0]  # Return the project name
    else:
        db.rollback()  # Rollback the transaction if no result is found
        return None

@app.route('/get_enquiry_project_name/<string:selected_client>/<string:selected_enq_project_id>')
def get_enquiry_project_name(selected_client, selected_enq_project_id):
    project_name = query_database_for_enquiry_project_name(selected_client, selected_enq_project_id)
    return jsonify({"project_name": project_name})

def get_project_ids():
    db = get_database()
    cursor = db.cursor()
    # Assuming your projects table has columns 'id' and 'client'
    cursor.execute('SELECT id, client FROM projects')
    projects = cursor.fetchall()
    project_ids = [{'id': row[0], 'client': row[1]} for row in projects]
    # print( project_ids)

    return project_ids

def get_project_ids_by_client(client_name):
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT id, client FROM projects WHERE client = ?', (client_name,))
    projects = cursor.fetchall()
    project_ids = [{'id': row[0], 'client': row[1]} for row in projects]
    return project_ids

def get_project_names():
    with get_database() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT project_name FROM projects')
        project_name = [row[0] for row in cursor.fetchall()]
        # print("..............get_project_name",project_name)
    return project_name

@app.route('/get_client_suggestions', methods=['GET'])
def get_client_suggestions():
    client_names = get_client_names()  
    query = request.args.get('query', '')  
    suggestions = [client for client in client_names if query.lower() in client.lower()]
    return jsonify({'suggestions': suggestions})

@app.route('/get_project_id_suggestions', methods=['GET'])
def get_project_id_suggestions():
    project_ids = get_project_ids()
    query = request.args.get('query', '') 
    suggestions = [project_id for project_id in project_ids if query.lower() in project_id.lower()]
    return jsonify({'suggestions': suggestions})

@app.route('/')
def index():
    user = get_current_user()
    return render_template('home.html', user=user)

from datetime import datetime, timedelta

def allowed_file(filename):
    allowed_extensions = {'txt', 'pdf', 'doc', 'png', 'jpg', 'jpeg', 'gif'}  
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

from io import BytesIO
def save_uploaded_file(file, ponumber):
    UPLOAD_FOLDER = 'data'  
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    if file:
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            return "Invalid file extension"
        try:
            # Save the file with the PONumber as the file name
            file_path = os.path.join(UPLOAD_FOLDER, f'{ponumber}.{file_extension}')
            file.save(file_path)
            return "File uploaded and saved successfully"
        except Exception as e:
            return f"Error uploading file: {str(e)}"
    return "No file provided"

@app.context_processor
def utility_processor():
    def getStatusColorClass(status):
        if status == 'Pending':
            return 'pending-color'
        elif status == 'Won':
            return 'won-color'
        elif status == 'Submitted':
            return 'submitted-color'
        elif status == 'Lost':
            return 'lost-color'
        return ''
    
    return dict(getStatusColorClass=getStatusColorClass)

@app.route('/delete_enquiry', methods=['DELETE'])
def delete_enquiry():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Unauthorized access'}), 401
    
    enquiry_number = request.args.get('enquiry_number')
    db = get_database()
    
    try:
        db.execute("DELETE FROM enquiries WHERE EnquiryNumber = ?", (enquiry_number,))
        db.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin_create_project/<int:enquiry_number>', methods=['GET', 'POST'])
def admin_create_project(enquiry_number):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username( user['name'])

    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (enquiry_number,))
    enquiry = cursor.fetchone()
    usernames = get_all_usernames()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    pmtable_cur = db.execute('SELECT * FROM pmtable WHERE project_id = ?', [enquiry_number])
    pmtable_rows = pmtable_cur.fetchall()
    return render_template('admin_templates/projects/admin_create_project.html', department_code=department_code, user=user,enquiry=enquiry,enquiry_number=enquiry_number,usernames=usernames,pmtable_rows=pmtable_rows)

def get_date_range():
    # Calculate the start date (30 days ago from today)
    start_date = datetime.now() - timedelta(days=30)

    # Generate a list of dates from start_date to today
    date_range = [start_date + timedelta(days=i) for i in range(31)]

    # Convert dates to strings in the format 'YYYY-MM-DD'
    date_strings = [date.strftime('%d-%m-%y') for date in date_range]

    return date_strings

@app.route('/employee_view_data')
def employee_view_data():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    username = user['name']
    cursor = db.execute('''SELECT  projectID FROM workingHours WHERE employeeID = ? ''', (username,))
    employee_department_pairs = cursor.fetchall()
    employee_data_dict = {}
    distinct_working_dates = []
    department_code = get_department_code_by_username(username)
    for pair in employee_department_pairs:
        projectID = pair['projectID']
        employee_data_cursor = db.execute(''' SELECT workingDate, hoursWorked FROM workingHours WHERE projectID = ? and employeeID=?''', (projectID,username))
        employee_data = employee_data_cursor.fetchall()
        total_hours_worked = sum(entry['hoursWorked'] for entry in employee_data)
        employee_data_dict[(projectID)] = {'data': employee_data,'total_hours': total_hours_worked}

        for entry in employee_data:
            working_date = entry['workingDate']
            parsed_date = parse_custom_date(working_date)
            if parsed_date and parsed_date not in distinct_working_dates:
                distinct_working_dates.append(parsed_date)

    distinct_working_dates.sort(key=lambda x: datetime.strptime(x, '%d-%m-%Y'), reverse=True)
    db.close()
    
    return render_template('employee_view_data.html', is_pm=is_pm,employee_data=employee_data_dict,department_code=department_code,distinct_working_dates=distinct_working_dates, parse_custom_date=parse_custom_date,user=username)

def check_project_status(project_id):
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT status FROM projects WHERE id = ?', (project_id,))
    result = cursor.fetchone()
    # db.close()
    if result:
        return result[0]  
    else:
        return 'unknown'

@app.route('/delete_projects', methods=['POST'])
def delete_projects():
    selected_projects = request.form.getlist('selected_projects')

    if selected_projects:
        # Delete the selected rows from the temp_workingHours table
        db = get_database()
        cursor = db.cursor()

        # Construct the SQL query to delete rows with matching projectIDs
        placeholders = ', '.join(['?'] * len(selected_projects))
        delete_query = f'DELETE FROM temp_workingHours WHERE projectID IN ({placeholders})'

        try:
            cursor.execute(delete_query, selected_projects)
            db.commit()
            flash(f'Selected projects deleted successfully', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Error deleting projects: {str(e)}', 'danger')
        finally:
            db.close()

    # Redirect back to the admin_view_data page
    return redirect(url_for('admin_view_data'))

from datetime import datetime

def convert_date_format(date_string):
    try:
        date_object = datetime.strptime(date_string, '%Y-%m-%d')
        formatted_date = date_object.strftime('%d %m %Y')
        # print('formatted_date: ', formatted_date)
        return formatted_date
    except ValueError:
        return None

@app.route('/log', methods=['POST'])
def log():
    data = request.get_json()
    print("Received data:", data)
    return jsonify({"message": "Log data received"})

from flask import session, redirect, url_for
from datetime import datetime, timedelta
app.config['SESSION_TIMEOUT'] = 20 * 60

def generate_date_range(start_date, end_date):
    start_date = datetime.strptime(start_date, "%d %m %Y")
    end_date = datetime.strptime(end_date, "%d %m %Y")
    date_range = [start_date + timedelta(days=x) for x in range((end_date - start_date).days + 1)]
    return date_range

def custom_date(value, format='%Y-%m-%d'):
    try:
        date_obj = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return date_obj.strftime(format)
    except ValueError:
        return value

def get_project_details(project_id):
    db = get_database()
    cursor = db.cursor()
    query = "SELECT *, strftime('%Y-%m-%d', start_time) AS formatted_start_time, strftime('%Y-%m-%d', end_time) AS formatted_end_time FROM projects WHERE id = ?"
    cursor.execute(query, (project_id,))
    project_details = cursor.fetchone()
    cursor.close()
    db.close()
    if project_details:
        keys = ('id','client', 'project_name', 'start_time', 'end_time', 'pm_status', 'pe_status', 'status', 'po_number', 'pm', 'pe','po_value')
        return dict(zip(keys, project_details))
    else:
        return None

def fetchone_for_edit(proid):
    user = get_current_user()
    db = get_database()
    pro_cur = db.execute('select * from projects where id = ?', [proid])
    single_pro = pro_cur.fetchone()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    return ( single_pro)

@app.route('/logout')
def logout():
    # Clear the session and remove the user key
    session.clear()
    session.pop('user', None)
    
    # Redirect to the home page after logging out
    return redirect(url_for('home'))

@app.route('/home')
def home():
    return render_template('home.html')

def get_all_usernames():
    db = get_database()
    result = db.execute('SELECT username FROM admin_user').fetchall()
    usernames = [row['username'] for row in result]
    return usernames

def get_department_code_for_username(username):
    conn = get_database()
    cursor = conn.cursor()
    cursor.execute('SELECT department_code FROM admin_user WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result:
        department_code = result[0]
        return department_code
    else:
        return None

def get_projects_for_user(username):
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM projects WHERE pm = ? AND pm_status = 1', [username])
    project_ids = [row[0] for row in cursor.fetchall()]
    # print("---------------------------------------------------------------",project_ids)
    return project_ids

from datetime import datetime
def parse_custom_date(date_string):
    # Try to parse the date string with different formats
    formats_to_try = ['%d %m %Y', '%d-%m-%Y']  # Add more formats if needed
    
    for date_format in formats_to_try:
        try:
            parsed_date = datetime.strptime(date_string, date_format).strftime('%d-%m-%Y')
            return parsed_date
        except ValueError:
            pass
    
    # If none of the formats worked, return None or handle the error as needed
    return None

@app.route('/admin_view_data/<int:project_id>')
def admin_view_data(project_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    db = get_database()
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    department_code = get_department_code_by_username( user['name'])

    cursor = db.execute('''SELECT DISTINCT employeeID, departmentID FROM workingHours WHERE projectID = ? ''', (project_id,))
    employee_department_pairs = cursor.fetchall()
    
    employee_data_dict = {}
    distinct_working_dates = []
    
    for pair in employee_department_pairs:
        employee_id = pair['employeeID']
        department_id = pair['departmentID']
        employee_data_cursor = db.execute(''' SELECT workingDate, hoursWorked FROM workingHours WHERE projectID = ? AND employeeID = ? AND departmentID = ? ''', (project_id, employee_id, department_id))
        employee_data = employee_data_cursor.fetchall()
        # Calculate the total hours worked for this employee
        total_hours_worked = sum(entry['hoursWorked'] for entry in employee_data)
        # Store the employee data along with the total hours
        employee_data_dict[(employee_id, department_id)] = {'data': employee_data,'total_hours': total_hours_worked}
        for entry in employee_data:
            working_date = entry['workingDate']
            # print("..............................", working_date )
            # Use the custom date parser to extract and format the date
            parsed_date = parse_custom_date(working_date)
            if parsed_date and parsed_date not in distinct_working_dates:
                distinct_working_dates.append(parsed_date)

    distinct_working_dates.sort(key=lambda x: datetime.strptime(x, '%d-%m-%Y'), reverse=True)
    
    user = get_current_user()
    pro_cur = db.execute('select * from projects where id = ?', [project_id])
    single_pro = pro_cur.fetchone()
    project_details = get_project_details(project_id)
    db.close()
    return render_template('admin_templates/projects/admin_project_view_data.html', employee_data=employee_data_dict,project_details=project_details,user=user,is_pm = is_pm,department_code=department_code,
                             distinct_working_dates=distinct_working_dates, parse_custom_date=parse_custom_date)

def query_database_for_department_code(username):
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT department_code FROM admin_user WHERE username = ?", (username,))
    department_data = cursor.fetchone()
    # conn.close()
    if department_data:
        department_code = department_data[0]
        return {"department_code": department_code}
    else:
        return {"department_code": None}

@app.route('/get_department_code/<username>')
def get_department_code(username):
    department_data = query_database_for_department_code(username)
    
    department_code = department_data.get('department_code')
    return jsonify({"department_code": department_code})

def query_database_for_project_name(selected_client, selected_project_id):
    selected_client = selected_client.strip()
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT project_name FROM projects WHERE id = ? AND client = ?", (selected_project_id, selected_client))
    result = cursor.fetchone()

    if result:
        return result[0]  # Return the project name
    else:
        return None 

@app.route('/get_project_name/<string:selected_client>/<string:selected_project_id>')
def get_project_name(selected_client, selected_project_id):
    project_name = query_database_for_project_name(selected_client, selected_project_id)
    return jsonify({"project_name": project_name})

@app.route('/get_project_ids_suggestions/<client>')
def get_project_ids_suggestions(client):
    try:
        db = get_database()
        cursor = db.cursor()
        # print('.......client..........',client)
        cursor.execute("SELECT id FROM projects WHERE client = ?", (client,))
        project_ids = [row[0] for row in cursor.fetchall()]
        # print('.......project_ids..........',project_ids)
        return jsonify(project_ids=project_ids)
    except Exception as e:
        return jsonify(project_ids=[]), 500  # Return an empty list and a 500 status code for error
    finally:
        cursor.close()
        db.close()

####-----------------------------------------------profile---------------------------------------------------------------------------------------------------------

def get_project_pm(project_id):
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
    result = cursor.fetchone()
    return result[0] if result else None

from datetime import datetime, timedelta

def parse_lead_time(lead_time_str):
    # print("......lead_time_str..............",lead_time_str)
    if not lead_time_str:
        return None
    lead_time_str = lead_time_str.strip().lower()
    # print("...split...lead_time_str..............",lead_time_str)

    try:
        if 'day' in lead_time_str:
            days = int(lead_time_str.split()[0])
            return timedelta(days=days)
        elif 'week' in lead_time_str:
            weeks = int(lead_time_str.split()[0])
            return timedelta(weeks=weeks)
    except:
        return None

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    employee_id = user['name']
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    # Fetch total_cost and formatted_date for past 30 days
    from datetime import datetime, timedelta
    current_year = datetime.now().year  # Get the current year
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    cursor.execute(""" SELECT formatted_date, SUM(total_cost)  FROM workingHours  WHERE employeeID = ?  AND formatted_date >= ? GROUP BY formatted_date
                    ORDER BY formatted_date """, (user['name'], thirty_days_ago))
    data = cursor.fetchall()
    dates = [datetime.strptime(row[0], '%Y-%m-%d').strftime('%d/%m') for row in data]
    total_costs = [row[1] for row in data]


    query = """ SELECT id  FROM projects  WHERE pm = ?  OR project_members LIKE ?;"""
    cursor.execute(query, (user['name'], f"%{user['name']}%"))
    project_ids = [row[0] for row in cursor.fetchall()]
    
    pr_data = {
        "pending": 0,
        "approved": 0,
        "total": 0
    }
    
    current_year = str(datetime.now().year)
    current_year_short = str(current_year)[2:]
    
    if user_access["toggle_PR_all_approve"] == 'On':

        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Processed' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Processed' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM created_pr
            WHERE substr(PR_Date, -2) = ?;
        """
        cursor.execute(query, (current_year_short,))

    else:
        user_is_pm = any(user['name'] == get_project_pm(pid) for pid in project_ids)

        if user_is_pm:
            query = """
                SELECT 
                    COUNT(CASE WHEN status != 'Processed' THEN 1 END) AS pending_count,
                    COUNT(CASE WHEN status = 'Processed' THEN 1 END) AS approved_count,
                    COUNT(*) AS total_count
                FROM created_pr
                WHERE substr(PR_Date, -2) = ?;
            """
            cursor.execute(query, (current_year_short,))
        else:
            query = """
                SELECT 
                    COUNT(CASE WHEN status != 'Processed' THEN 1 END) AS pending_count,
                    COUNT(CASE WHEN status = 'Processed' THEN 1 END) AS approved_count,
                    COUNT(*) AS total_count
                FROM created_pr 
                WHERE created_by = ? AND substr(PR_Date, -2) = ?;
            """
            cursor.execute(query, (user['name'], current_year_short))
    
    result = cursor.fetchone()
    pr_data["pending"] = result[0]
    pr_data["approved"] = result[1]
    pr_data["total"] = result[2]


    # Initialize po_counts
    po_counts = {
        "pending": 0,
        "approved": 0,
        "total": 0
    }

    if user_access["toggleProf_po_View_All"] == 'On':
        # If toggle is On, consider all POs from the current year
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Closed' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Closed' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM created_po
            WHERE substr(PO_Date, -2) = ?; 
        """
        cursor.execute(query, (current_year_short,))

    else:
        # If toggle is Off, consider only POs created or approved by the user in the current year
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Closed' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Closed' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM created_po 
            WHERE (created_by = ? OR approved_by = ?) AND substr(PO_Date,-2) = ?;
        """
        cursor.execute(query, (user['name'], user['name'], current_year_short))

    result = cursor.fetchone()

    po_counts["pending"] = result[0]
    po_counts["approved"] = result[1]
    po_counts["total"] = result[2]
    
    payment_request_counts = {
        "pending": 0,
        "approved": 0,
        "total": 0
    }
    current_year = str(datetime.now().year)

    if user_access["toggleView_pro_Request_view_all"] == 'On':
        # If toggle is On, consider all payment requests from the current year
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Paid' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Paid' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM payment_request
            WHERE strftime('%Y', pay_date) = ?;
        """
        cursor.execute(query, (current_year,))

    else:
        # If toggle is Off, filter by created_by or approved_by in the current year
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Paid' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Paid' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM payment_request 
            WHERE (created_by = ? OR approved_by = ?) AND strftime('%Y', pay_date) = ?;
        """
        cursor.execute(query, (user['name'], user['name'], current_year))

    result = cursor.fetchone()

    payment_request_counts["pending"] = result[0] if result[0] is not None else 0
    payment_request_counts["approved"] = result[1] if result[1] is not None else 0
    payment_request_counts["total"] = result[2] if result[2] is not None else 0
    
    claims_counts = {
        "pending": 0,
        "approved": 0,
        "total": 0
    }

    if user_access["toggle_prof_view_all_Claims"] == 'On':
        # If toggle is On, consider all claims
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Approved' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Approved' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM claims;
        """
        cursor.execute(query)
    
    else:
        # If toggle is Off, consider only claims submitted by the user
        query = """
            SELECT 
                COUNT(CASE WHEN status != 'Approved' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN status = 'Approved' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM claims 
            WHERE claim_by = ?;
        """
        cursor.execute(query, (user['name'],))

    # Fetch the result
    result = cursor.fetchone()

    claims_counts["pending"] = result[0] if result[0] is not None else 0
    claims_counts["approved"] = result[1] if result[1] is not None else 0
    claims_counts["total"] = result[2] if result[2] is not None else 0

    project_request_counts = {
        "pending": 0,
        "approved": 0,
        "total": 0 }
    
    if user_access["toggleRequestedList"] == 'On':
        # If toggle is On, consider all project requests
        query = """
            SELECT 
                COUNT(CASE WHEN approved_status != 'Created' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN approved_status = 'Created' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM projects_request;
        """
        cursor.execute(query)
    else:
        # If toggle is Off, consider only project requests created by the user
        query = """
            SELECT 
                COUNT(CASE WHEN approved_status != 'Created' THEN 1 END) AS pending_count,
                COUNT(CASE WHEN approved_status = 'Created' THEN 1 END) AS approved_count,
                COUNT(*) AS total_count
            FROM projects_request 
            WHERE created_by = ?;
        """
        cursor.execute(query, (user['name'],))

    # Fetch the result
    result = cursor.fetchone()

    # Assign values while handling None cases
    project_request_counts["pending"] = result[0] if result[0] is not None else 0
    project_request_counts["approved"] = result[1] if result[1] is not None else 0
    project_request_counts["total"] = result[2] if result[2] is not None else 0

    # Query to get total hours, overtime, and cost
    query = """
        SELECT 
            COALESCE(SUM(hoursWorked), 0) AS total_hours,
            COALESCE(SUM(overtime_1_5 + overtime_2_0), 0) AS total_overtime,
            COALESCE(SUM(total_cost), 0) AS total_cost
        FROM workingHours
        WHERE employeeID = ? 
        AND strftime('%Y', formatted_date) = ?;
    """

    cursor.execute(query, (user['name'], str(current_year)))
    result = cursor.fetchone()
    
    # Ensure result is not None
    total_hours = result[0] if result and result[0] is not None else 0
    total_overtime = result[1] if result and result[1] is not None else 0
    total_cost = result[2] if result and result[2] is not None else 0

    # Initialize the leaves counts
    leaves_counts = {
        "pending": 0,
        "approved": 0,
        "total": 0
    }

    query = """
        SELECT 
            COUNT(CASE WHEN status != 'Approved' THEN 1 END) AS pending_count,
            COUNT(CASE WHEN status = 'Approved' THEN 1 END) AS approved_count,
            COUNT(*) AS total_count
        FROM leaves_approved
        WHERE employeeID = ?;
    """

    cursor.execute(query, (user['name'],))
    result = cursor.fetchone()

    # Add counts to the total
    leaves_counts["pending"] += result[0] if result[0] is not None else 0
    leaves_counts["approved"] += result[1] if result[1] is not None else 0
    leaves_counts["total"] += result[2] if result[2] is not None else 0

    card_data = {
        "timesheet": {
            "total_hours": total_hours,  
            "total_overtime": total_overtime, 
            "total_cost": total_cost
        },
        "pr_data": pr_data,  # Append pr_data
        "po_counts": po_counts,  # Append po_counts
        "payment_request_counts": payment_request_counts,  # Append payment_request_counts
        "claims_counts": claims_counts,  # Append claims_counts
        "project_request_counts": project_request_counts,  # Append project_request_counts
        'leaves_counts':leaves_counts
    }

    if department_code == 1000:
        query = """
            SELECT PO_no, Supplier_Name, do_staus, PO_Date, leat_time
            FROM created_po
            WHERE do_staus IS NOT NULL AND do_staus != 'Closed' ORDER BY id DESC
        """
        rows = db.execute(query).fetchall()
    
    else:
        query = """
            SELECT PO_no, Supplier_Name, do_staus, PO_Date, leat_time
            FROM created_po
            WHERE do_staus IS NOT NULL AND do_staus != 'Closed'
              AND created_by = ? ORDER BY id DESC
        """
        rows = db.execute(query, (user['name'],)).fetchall()
    
    po_list = []
   
    for po_no, supplier, status, po_date, lead_time in rows:
        po_date_obj = datetime.strptime(po_date, '%d-%m-%y')
        lead_delta = parse_lead_time(lead_time)
        if lead_delta:
            eta = po_date_obj + lead_delta
        else:
            eta = None
        po_list.append({
            'PO_no': po_no,
            'Supplier_Name': supplier,
            'do_status': status,
            'Estimated_Delivery_Date': eta.strftime('%Y-%m-%d') if eta else ''
        })
    
    if department_code == 1000:
        pending_enquiries = db.execute("""
            SELECT EnquiryNumber, Name, SubmitBeforeDate
            FROM enquiries
            WHERE status = 'Pending' ORDER BY EnquiryNumber DESC
        """).fetchall()
    
    else:
        pending_enquiries = db.execute("""
            SELECT EnquiryNumber, Name, SubmitBeforeDate
            FROM enquiries
            WHERE status = 'Pending' AND assigned_to = ? ORDER BY EnquiryNumber DESC
        """, (user['name'],)).fetchall()


    today = datetime.today()
    thirty_days_ago = today - timedelta(days=30)

    # Generate all dates in last 30 days
    date_list = [(thirty_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(31)]

    # Remove weekends
    date_list = [date for date in date_list if datetime.strptime(date, '%Y-%m-%d').weekday() < 5]

    # Get public holidays in this range
    holiday_query = """
        SELECT date FROM public_holidays
        WHERE date BETWEEN ? AND ?
    """
    holidays = db.execute(holiday_query, (date_list[0], date_list[-1])).fetchall()
    holiday_dates = {row['date'] for row in holidays}

    # Filter out public holidays
    working_dates = [d for d in date_list if d not in holiday_dates]

    # Get worked hours grouped by date
    hours_query = """
        SELECT formatted_date, SUM(totalhours) as total_hrs
        FROM workingHours
        WHERE formatted_date BETWEEN ? AND ?
        AND employeeID = ?
        GROUP BY formatted_date
    """
    hours_results = db.execute(hours_query, (date_list[0], date_list[-1], user['name'])).fetchall()
    hours_dict = {row['formatted_date']: row['total_hrs'] for row in hours_results}

    # Compile timesheet data with missing dates filled as 0
    timesheet_data = []
    for date in sorted(working_dates, reverse=True):
        total_hrs = hours_dict.get(date, 0)
        if total_hrs < 8:
            balance_hrs = round(8.0 - total_hrs, 2)
            timesheet_data.append({
                'date': date,
                'balance_hrs': balance_hrs
            })




    from datetime import datetime

    # --------- PROJECT STATUS COUNTS ----------
    if department_code == 1000:
        query = """SELECT status, COUNT(*) as count FROM projects GROUP BY status"""
        project_status_rows = db.execute(query).fetchall()
    else:
        query = """SELECT status, COUNT(*) as count FROM projects WHERE project_members LIKE ? GROUP BY status"""
        project_status_rows = db.execute(query, (f"%{user['name']}%",)).fetchall()

    plot_prj_status_counts = {row['status']: row['count'] for row in project_status_rows} if project_status_rows else {}

    # --------- ENQUIRY STATUS COUNTS ----------
    if department_code == 1000:
        query = """SELECT status, COUNT(*) as count  FROM enquiries  WHERE strftime('%Y', EnquiryReceived) = ?  GROUP BY status"""
        enquiry_status_rows = db.execute(query, (str(current_year),)).fetchall()
    else:
        query = """SELECT status, COUNT(*) as count FROM enquiries WHERE assigned_to = ? AND strftime('%Y', EnquiryReceived) = ? GROUP BY status"""
        enquiry_status_rows = db.execute(query, (user['name'], str(current_year))).fetchall()

    plot_leads_status_counts = {row['status']: row['count'] for row in enquiry_status_rows} if enquiry_status_rows else {}
    plot_leads_status_counts = {k: v for k, v in plot_leads_status_counts.items() if k not in [None, '']}


    # --------- DELIVERY ORDER (DO) COUNT ----------
    if department_code == 1000:
        query = "SELECT COUNT(*) AS count FROM created_do"
        do_result = db.execute(query).fetchone()
    else:
        query = "SELECT COUNT(*) AS count FROM created_do WHERE created_by = ?"
        do_result = db.execute(query, (user['name'],)).fetchone()

    do_count = do_result['count'] if do_result and do_result['count'] is not None else 0

    # --------- WORKING HOURS SUMMARY ----------
    current_year = datetime.now().year
    if department_code == 1000:
        query = """
            SELECT 
                SUM(hoursWorked) AS total_hours,
                SUM(overtime_1_5) AS total_overtime_1_5,
                SUM(overtime_2_0) AS total_overtime_2_0
            FROM workingHours 
            WHERE strftime('%Y', formatted_date) = ?
        """
        hours_result = db.execute(query, (str(current_year),)).fetchone()
    else:
        query = """
            SELECT 
                SUM(hoursWorked) AS total_hours,
                SUM(overtime_1_5) AS total_overtime_1_5,
                SUM(overtime_2_0) AS total_overtime_2_0
            FROM workingHours 
            WHERE employeeID = ?
        """
        hours_result = db.execute(query, (user['name'],)).fetchone()

    plot_time_sheet_counts = {
        "Standered": hours_result['total_hours'] or 0,
        " 1.5_X ": hours_result['total_overtime_1_5'] or 0,
        "2.0_X": hours_result['total_overtime_2_0'] or 0
    } if hours_result else {"Standered": 0, " 1.5_X ": 0, "2.0_X": 0}

    # --------- PURCHASE VALUE COUNTS ----------
    plot_purcahse_value = {
        "PR's": pr_data.get("total", 0),
        "PO's": po_counts.get("total", 0),
        "ER's": payment_request_counts.get("total", 0),
        "DO's": do_count
    }



    print("..........plot_time_sheet_counts..............",plot_time_sheet_counts)
    print("..........plot_purcahse_value..............",plot_purcahse_value)
    print("..........plot_prj_status_counts..............",plot_prj_status_counts)
    print("..........plot_leads_status_counts..............",plot_leads_status_counts)


    return render_template('admin_templates/profile/profile.html', user=user,department_code=department_code,user_access=user_access,
          dates=dates, total_costs=total_costs,card_data=card_data, pending_enquiries=pending_enquiries,po_list=po_list,timesheet_data=timesheet_data,
          plot_time_sheet_counts=plot_time_sheet_counts,plot_prj_status_counts=plot_prj_status_counts,
          plot_purcahse_value=plot_purcahse_value,plot_leads_status_counts=plot_leads_status_counts
          )

def check_leave_overlap(employee_id, startdate, enddate):
    db = get_database()
    cursor = db.cursor()
    if isinstance(startdate, str):
        startdate = datetime.strptime(startdate, "%Y-%m-%d")  # Convert string to datetime object
    if isinstance(enddate, str):
        enddate = datetime.strptime(enddate, "%Y-%m-%d")
    current_date = startdate
    conflicting_leave = None  # Initialize conflicting_leave with None
    while current_date <= enddate:
        # Format current_date to match the database date format (YYYY-MM-DD)
        formatted_date = current_date.strftime("%Y-%m-%d")
        cursor.execute("SELECT * FROM leaves WHERE employeeID = ? AND leave_date = ?", (employee_id, formatted_date))
        conflicting_leave = cursor.fetchone()
        if conflicting_leave:
            break
        else:
            current_date += timedelta(days=1)
    return conflicting_leave

from datetime import datetime, timedelta
from flask import request, jsonify

@app.route('/calculate_days', methods=['GET'])
def calculate_days():
    db = get_database()
    cursor = db.cursor()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    from datetime import datetime, timedelta

    lev_startdate = datetime.strptime(start_date, '%Y-%m-%d')
    lev_enddate = datetime.strptime(end_date, '%Y-%m-%d')
    current_year = lev_startdate.year

    # Fetch current year's public holidays
    result = cursor.execute('SELECT date FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
    public_holidays = {datetime.strptime(row['date'], '%Y-%m-%d').date() for row in result.fetchall()}

    calculated_number_of_days = 0
    current_date = lev_startdate.date()
    
    while current_date <= lev_enddate.date():
        if current_date.weekday() not in (5, 6) and current_date not in public_holidays:
            calculated_number_of_days += 1
        current_date += timedelta(days=1)

    print('days........', calculated_number_of_days)

    return jsonify({'days': calculated_number_of_days})

def check_role_exists(employee_name, role_code):
    db = get_database()
    cursor = db.cursor()
    query = """ SELECT 1 FROM roles WHERE employee = ? AND (primary_role_code = ? OR sencondary_role_code = ?) LIMIT 1; """
    cursor.execute(query, (employee_name, role_code, role_code))
    result = cursor.fetchone()
    exists = result is not None
    print(exists)
    return exists

def get_projects_by_pm(user_name):
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute("SELECT id FROM projects WHERE pm = ? AND status != 'closed'", (user_name,))

    projects = cursor.fetchall()
    project_ids = [project['id'] for project in projects]
    
    return project_ids

@app.route('/prof_pr', methods=['GET', 'POST'])
def prof_pr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    project_ids = get_projects_by_pm(user['name'])

    if user_access and user_access.get("toggle_PR_all_view") == 'On':  
        cursor.execute('SELECT * FROM created_pr ORDER BY id DESC')
    else:
        cursor.execute('SELECT * FROM created_pr WHERE created_by = ? ORDER BY id DESC', (user['name'],))
    pr_query = cursor.fetchall()
    
    columns = [desc[0] for desc in cursor.description]
    pr_data = [dict(zip(columns, pr)) for pr in pr_query]
    
    project_pr_data = []

    for project_id in project_ids:
        cursor.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC', (project_id,))
        pr_rows = cursor.fetchall()

        project_pr_data.append({
            'project_id': project_id,
            'prs': [dict(zip(columns, pr)) for pr in pr_rows]
        })
    
    seen_pr_no = set()
    merged_pr_data = []

    for pr in pr_data:
        if pr['PR_no'] not in seen_pr_no:
            merged_pr_data.append(pr)
            seen_pr_no.add(pr['PR_no'])

    for project in project_pr_data:
        for pr in project['prs']:
            if pr['PR_no'] not in seen_pr_no:
                merged_pr_data.append(pr)
                seen_pr_no.add(pr['PR_no'])

    for row in merged_pr_data:
        pr_no = row['PR_no']
        project_id = int(row.get('project_id', 0)) if row.get('project_id') else None  # Convert project_id to int

        cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
        pm_result = cursor.fetchone()
        row['pm'] = 'Yes' if pm_result and user['name'] == pm_result[0] else 'No'
        
        cursor.execute("SELECT SUM(total), AVG(GST) FROM pr_items WHERE pr_number = ?", (pr_no,))
        total, gst_percent = cursor.fetchone()
        total = total if total else 0
        gst_percent = gst_percent if gst_percent else 0  
        gst_amount = (total * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
        
        cursor.execute("SELECT Discount FROM created_pr WHERE PR_no = ?", (pr_no,))
        discount_row = cursor.fetchone()
        discount_percent = float(discount_row[0]) if discount_row and discount_row[0] else 0
        discount_amount = total * (discount_percent / 100)
        amount_after_discount  = total - discount_amount
        exchange_rate = float(row.get('Exchange_rate', 1.0) or 1.0)
        gst_amount = (amount_after_discount  * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
        total_with_gst = amount_after_discount  + gst_amount
        row['amount'] = round(amount_after_discount / exchange_rate, 2)
        row['GST'] = round(gst_amount / exchange_rate, 2)
        row['total'] = round(total_with_gst / exchange_rate, 2)
        row['id'] = row.get('id', None)

        # ✅ Ensure 'id' exists, default to None
        row['id'] = row.get('id', None)

    grouped_df = pd.DataFrame(merged_pr_data)

    # ✅ Check if 'id' column exists before sorting
    if 'id' in grouped_df.columns:
        grouped_df = grouped_df.sort_values(by='id', ascending=False)
    else:
        print("Warning: 'id' column not found in DataFrame.")  # Debugging step


    if user_access and user_access.get("togglecreate_PR_All") == 'On':
        query = '''SELECT id FROM projects WHERE status != 'Closed' ORDER BY id DESC;'''
        cursor.execute(query)
    else:
        query = '''SELECT id FROM projects WHERE status != 'Closed' AND (pm = ? OR project_members LIKE ?) ORDER BY id DESC;'''
        cursor.execute(query, (user['name'], f"%{user['name']}%"))

    projects = [row[0] for row in cursor.fetchall()]  # Flat list: [101, 100, 99, ...]


    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    return render_template('admin_templates/profile/prof_pr.html', user=user, department_code=department_code, user_access=user_access, grouped_df=grouped_df,
                          gst=gst, projects=projects,Supplier_Names=Supplier_Names)
               
def send_email_notifications(valid_emails, pr_date, project_id, approved_by, created_by, PR_no):
    """Send emails asynchronously to avoid blocking the main thread."""
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    valid_emails = [email for email in valid_emails if re.match(email_regex, email)]

    if valid_emails:
        PR_Approval_Notification(valid_emails, pr_date, project_id, approved_by, created_by, PR_no)

import threading
@app.route('/approve_pr', methods=['POST'])
def approve_pr():
    data = request.get_json()
    PR_no = data.get('PR_no')

    db = get_database()
    cursor = db.cursor()
    user = get_current_user()
    user_name = user['name']

    # Update PR status
    cursor.execute('UPDATE created_pr SET status = ?, approved_by = ? WHERE PR_no = ?', 
                   ('Approved', user_name, PR_no)) 
    cursor.execute("SELECT PR_no, project_id, created_by, PR_Date FROM created_pr WHERE PR_no = ?", (PR_no,))
    result = cursor.fetchone()
    db.commit()

    if result:
        PR_no, project_id, created_by, pr_date = result
        all_emails_set = set()

        # Fetch project members' emails
        cursor.execute("SELECT pm, project_members FROM projects WHERE id = ?", (project_id,))
        project_row = cursor.fetchone()
        if project_row:
            pm, project_members = project_row
            project_members = project_members or ''
            all_members = {pm} | set(project_members.split(','))
            placeholders = ','.join('?' * len(all_members))
            cursor.execute(f"SELECT name FROM admin_user WHERE username IN ({placeholders})", list(all_members))
            all_emails_set.update([row[0] for row in cursor.fetchall()])

        # Fetch email of `created_by`
        cursor.execute('SELECT name FROM admin_user WHERE username = ?', (created_by,))
        created_by_row = cursor.fetchone()
        if created_by_row:
            all_emails_set.add(created_by_row[0])
        else:
            all_emails_set.add('sairam@gmail.com')

        query = """
            SELECT username 
            FROM admin_user 
            WHERE department_code IN (14, 1000) OR secondary_role_code IN (14, 1000);
        """
        all_emails_set.update(row[1] for row in cursor.fetchall())
        print("...all_emails_set..............",all_emails_set)

        # Send emails in a separate thread
        # email_thread = threading.Thread(target=send_email_notifications, 
        #                                 args=(all_emails_set, pr_date, project_id, user_name, created_by, PR_no))
        # email_thread.start()

    return jsonify({'message': 'PR Approved successfully!'})

@app.route('/get_pr_details')
def get_pr_details():
    PR_no = request.args.get('PR_no')
    db = get_database()
    cursor = db.cursor()

    # Get PR Details
    pr_details = cursor.execute("SELECT * FROM created_pr WHERE PR_no = ?", (PR_no,)).fetchone()

    if not pr_details:
        return jsonify({'success': False, 'message': 'Purchase Request not found'})

    pr_dict = dict(pr_details)
    discount_percent = float(pr_dict.get('Discount') or 0)

    # Get total and GST %
    cursor.execute("SELECT SUM(total), AVG(GST) FROM pr_items WHERE pr_number = ?", (PR_no,))
    total, gst_percent = cursor.fetchone()
    total = float(total or 0)
    gst_percent = float(gst_percent or 0)

    # Apply discount
    discount_amount = (discount_percent / 100.0) * total if discount_percent > 0 else 0.0
    discounted_total = total - discount_amount

    # Apply GST only if GST % is not 1 (your logic for excluding negative/invalid GST)
    gst_amount = (discounted_total * gst_percent / 100.0) if gst_percent != 1 and gst_percent > 0 else 0.0

    total_amount = discounted_total + gst_amount

    # Get PR items and PO details
    items = cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (PR_no,)).fetchall()
    po_details = cursor.execute("SELECT * FROM created_po WHERE PR_no_ref = ?", (PR_no,)).fetchone()

    return jsonify({
        'success': True,
        'amount': total,
        'discount_percent': discount_percent,
        'discount_amount': round(discount_amount, 2),
        'discounted_total': round(discounted_total, 2),
        'gst_amount': round(gst_amount, 2),
        'total': round(total_amount, 2),
        'pr_details': pr_dict,
        'po_details': dict(po_details) if po_details else {},
        'items': [dict(item) for item in items],
    })


@app.route('/get_po_details')
def get_po_details():
    PO_no = request.args.get('PO_no')
    db = get_database()
    cursor = db.cursor()
    po_details = cursor.execute("SELECT * FROM created_po WHERE PO_no = ?", (PO_no,)).fetchone()
    po_dict = dict(po_details)
    discount_percent = float(po_dict.get('Discount') or 0)
    # print(".......discount_percent......",discount_percent)
    cursor.execute("SELECT SUM(total), AVG(GST) FROM po_items WHERE PO_number = ?", (PO_no,))
    amount, gst_percent = cursor.fetchone()
    amount = amount if amount else 0

    gst_percent = gst_percent if gst_percent else 0  
    if gst_percent != 1:
        gst_amount = (amount * gst_percent / 100) if gst_percent else 0
    else:
        gst_amount = 0
    total = amount + gst_amount


    discount_amount = (discount_percent / 100.0) * amount if discount_percent > 0 else 0.0
    discounted_total = amount - discount_amount
    gst_amount = (discounted_total * gst_percent / 100.0) if gst_percent != 1 and gst_percent > 0 else 0.0
    total_amount = discounted_total + gst_amount

    items = cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (PO_no,)).fetchall()

    if not po_details:
        return jsonify({'success': False, 'message': 'Purchase Order not found'})
    return jsonify({
        'success': True,
        'amount': amount,
        'discount_percent': discount_percent,
        'discount_amount': round(discount_amount, 2),
        'discounted_total': round(discounted_total, 2),
        'gst_amount': round(gst_amount, 2),
        'total': round(total_amount, 2),

        'po_details': dict(po_details),
        'items': [dict(item) for item in items],
    })

def parse_po_lead_time(lead_time_str):
    from datetime import timedelta

    if not lead_time_str:
        return None
    lead_time_str = lead_time_str.strip().lower()


    parts = lead_time_str.split()
    if len(parts) < 2:
        return None  # Not enough parts (example: "5" without "days/weeks")

    # Try parsing the number only if it’s a proper integer
    number_part = parts[0]

    if not number_part.isdigit():
        return None  # Skip non-numeric or ranged values like "8-10"

    number = int(number_part)
    unit = parts[1]

    if 'day' in unit:
        return timedelta(days=number)
    elif 'week' in unit:
        return timedelta(weeks=number)
    elif 'month' in unit:
        return timedelta(days=number * 30)  # Approximate 1 month = 30 days
    else:
        return None  # Unknown unit

@app.route('/prof_po', methods=['GET', 'POST'])
def prof_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    project_ids = get_projects_by_pm(user['name'])
    
    if user_access and user_access.get("toggleProf_po_View_All") == 'On':
        cursor.execute('SELECT * FROM created_po ORDER BY id DESC')
    else:
        cursor.execute('SELECT * FROM created_po WHERE created_by = ? ORDER BY id DESC', (user['name'],))
    pr_query = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    pr_data = [dict(zip(columns, pr)) for pr in pr_query]
    
    project_pr_data = []

    for project_id in project_ids:
        cursor.execute('SELECT * FROM created_po WHERE project_id = ? ORDER BY id DESC', (project_id,))
        pr_rows = cursor.fetchall()

        project_pr_data.append({
            'project_id': project_id,
            'prs': [dict(zip(columns, pr)) for pr in pr_rows]
        })
    
    seen_pr_no = set()
    merged_pr_data = []

    for pr in pr_data:
        if pr['PO_no'] not in seen_pr_no:
            merged_pr_data.append(pr)
            seen_pr_no.add(pr['PO_no'])

    for project in project_pr_data:
        for pr in project['prs']:
            if pr['PO_no'] not in seen_pr_no:
                merged_pr_data.append(pr)
                seen_pr_no.add(pr['PO_no'])

    from datetime import datetime, timedelta

    for row in merged_pr_data:
        pr_no = row['PO_no']
        project_id = row['project_id']  # Use project_id directly here
        cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
        pm_result = cursor.fetchone()
        if pm_result and user['name'] == pm_result[0]:
            row['pm'] = 'Yes'
        else:
            row['pm'] = 'No'
        
        cursor.execute("SELECT SUM(total), AVG(GST) FROM po_items WHERE PO_number = ?", (pr_no,))
        total, gst_percent = cursor.fetchone()
        total = total if total else 0
        gst_percent = gst_percent if gst_percent else 0  
        if gst_percent != 1:
            gst_amount = (total * gst_percent / 100) if gst_percent else 0
        else:
            gst_amount = 0

        cursor.execute("SELECT Discount FROM created_po WHERE PO_no = ?", (pr_no,))
        discount_row = cursor.fetchone()
        discount_percent = float(discount_row[0]) if discount_row and discount_row[0] else 0
        discount_amount = total * (discount_percent / 100)
        amount_after_discount  = total - discount_amount
        exchange_rate = float(row.get('Exchange_rate', 1.0) or 1.0)
        gst_amount = (amount_after_discount  * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
        total_with_gst = amount_after_discount  + gst_amount
        row['amount'] = round(amount_after_discount / exchange_rate, 2)
        row['GST'] = round(gst_amount / exchange_rate, 2)
        row['total'] = round(total_with_gst / exchange_rate, 2)



        po_date_str = row['PO_Date']  # Corrected the column name here to match the key in row
        lead_time_str = row['leat_time']  # 


        if po_date_str and lead_time_str:
            # Adjusted the format to '%y-%m-%d' to match '25-04-25'
            po_date = datetime.strptime(po_date_str, '%y-%m-%d')  # Convert PO date to datetime
            lead_time = parse_po_lead_time(lead_time_str)


            if lead_time:
                delivery_date = po_date + lead_time
                row['delivery_date'] = delivery_date.strftime('%y-%m-%d')  # Format delivery date as 'YYYY-MM-DD'
                print(".....delivery_date.......", delivery_date)
            else:
                row['delivery_date'] = ''  # If lead time is not valid, show 'N/A'
        else:
            row['delivery_date'] = ''  # If PO date or lead time is missing, show 'N/A'




    grouped_df = pd.DataFrame(merged_pr_data)
    grouped_df = grouped_df.sort_values(by='id', ascending=False)
    print(grouped_df.head(5))

    return render_template('admin_templates/profile/prof_po.html', user=user, department_code=department_code, user_access=user_access, grouped_df=grouped_df)

@app.route('/prof_claim', methods=['GET', 'POST'])
def prof_claim():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    show = 'project'
    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT Vehicle_number FROM vehicle')
    vehicle_numbers = sorted([row[0] for row in cursor.fetchall()])
    user_access = get_employee_access_control(user['name'])
    # query = ''' SELECT id AS id, project_name AS name FROM projects WHERE status != 'Closed' ORDER BY id DESC'''
    # cursor.execute(query)
    # combined_data = cursor.fetchall()
    projects_raw = db.execute("SELECT id AS id, project_name AS name FROM projects WHERE status != 'Closed' ORDER BY id DESC").fetchall()
    combined_data = [(row['id'], row['name']) for row in projects_raw]
    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    if user_access and user_access.get("toggle_prof_view_all_Claims") == 'On':
        query = """SELECT * FROM claims WHERE claim_id NOT LIKE 'E%' ORDER BY id DESC;"""
        cursor.execute(query)  # Execute query for all claims
    else:
        query = """SELECT * FROM claims WHERE claim_by = ? AND claim_id NOT LIKE 'E%' ORDER BY id DESC;"""
        params = (user['name'],)
        cursor.execute(query, params)  # Execute query for specific user

    claims_data = cursor.fetchall()  # Fetch all results

    return render_template('admin_templates/profile/prof_claim.html', department_code=department_code, user=user, 
                       claims_data=claims_data, gst=gst, show=show, user_access=user_access,vehicle_numbers=vehicle_numbers, projects=combined_data)

@app.route('/get_vendor_suggestions')
def get_vendor_suggestions():
    db = get_database()
    cursor = db.cursor()
    term = request.args.get('term', '')
    results = db.execute("SELECT company_name FROM vendors_details WHERE company_name LIKE ?", (f"%{term}%",)).fetchall()
    suggestions = [row['company_name'] for row in results]
    return jsonify(suggestions)

@app.route('/get_itemname_suggestions', methods=['GET'])
def get_itemname_suggestions():
    db = get_database()
    cursor = db.cursor()
    term = request.args.get('term', '')
    # Query the database for item names that match the term
    query = f"SELECT itemname FROM claimed_items WHERE itemname LIKE ?"
    results = db.execute(query, ('%' + term + '%',)).fetchall()
    # Extract item names from the results
    itemnames = [result[0] for result in results]
    return jsonify(itemnames)

@app.route('/project_claim', methods=['POST'])
def project_claim():
    from datetime import datetime
    import re

    db = get_database()
    cursor = db.cursor()
    claim_by = get_current_user()['name']
    current_date = datetime.now().date()
    current_year = datetime.now().year
    date = datetime.now().strftime("%Y-%m-%d")

    # Get form data
    project_ids = request.form.getlist('project_id[]')
    row_indexs = request.form.getlist('row_index[]')
    categories_codes = request.form.getlist('category_subcategory[]')
    purchase_dates = request.form.getlist('purcahse_date[]')
    # print("............purchase_dates.............",purchase_dates)
    supplier_names = request.form.getlist('Supplier_name[]')
    item_names = request.form.getlist('item_name[]')
    invoice_numbers = request.form.getlist('invoice_number[]')
    currencies = request.form.getlist('currency[]')
    rates = request.form.getlist('rate[]')
    gst_percents = request.form.getlist('gst_percent[]')
    amounts = request.form.getlist('amount[]')
    gst_values = request.form.getlist('gst_value[]')
    totals = request.form.getlist('total[]')
    files = request.files.getlist('attachment[]')

    footer_total_amount = float(request.form.get('footer_total_amount', '0.00').replace(',', ''))
    footer_total_gst = float(request.form.get('footer_total_gst', '0.00').replace(',', ''))
    footer_total_final = float(request.form.get('footer_total_final', '0.00').replace(',', ''))
    to_mail = request.form.get('footer_total_final', '0.00')

    comments = request.form['comments']
    ex_claim = request.form.get('existingprjcalim', '').strip()

    category_mapping = {
        "2001": "Mechanical", "2002": "Electrical", "2003": "Instruments", "2004": "PLC, Software, Hardware",
        "2005": "Panel Hardware", "2006": "Consumables", "2007": "Tools", "2008": "Civil", "2009": "Computer"
    }

    categories_names = [category_mapping.get(code, "Unknown Category") for code in categories_codes]

    # Determine claim ID
    latest_claim_no = ''
    if ex_claim:
        # Delete existing claim and its items
        cursor.execute("DELETE FROM claimed_items WHERE claim_no = ?", (ex_claim,))
        cursor.execute("DELETE FROM claims WHERE claim_id = ?", (ex_claim,))
        db.commit()

        # Generate suffix if needed
        match = re.match(r"(P-\d{2}-\d{4})(?:\((\d+)\))?", ex_claim)
        if match:
            base_claim = match.group(1)
            suffix = match.group(2)
            new_suffix = int(suffix) + 1 if suffix else 1
            latest_claim_no = f"{base_claim}({new_suffix})"
        else:
            latest_claim_no = ex_claim  # fallback
    else:
        # Create new claim number
        cursor.execute('SELECT id FROM claims ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        last_claim_no = result[0] if result else 0
        formatted_claim_no = f"{last_claim_no + 1:04d}"
        latest_claim_no = f"P-{str(current_year)[-2:]}-{formatted_claim_no}"

    # Insert new claim
    cursor.execute('''INSERT INTO claims (claim_by, claim_id, claim_date, status, comments, amount, gst_value, claim_Total, claim_type, balance)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)''',
                   (claim_by, latest_claim_no, current_date, 'Pending', comments,
                    footer_total_amount, footer_total_gst, footer_total_final, 'project',footer_total_final))
    db.commit()

    # Insert claim items
    for i in range(len(project_ids)):
        cursor.execute('''INSERT INTO claimed_items (claim_by, projectid, Category, Category_code, date, 
            vendor, itemname, invoice_number, Currency, Rate, gst_percent, amount, gst_value, total, claim_no, claim_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (claim_by, project_ids[i], categories_names[i], categories_codes[i], purchase_dates[i],
             supplier_names[i], item_names[i], invoice_numbers[i], currencies[i], rates[i], gst_percents[i],
             amounts[i], gst_values[i], totals[i], latest_claim_no, 'project'))


        clean_name = supplier_names[i].strip()
        clean_name = supplier_names[i].strip()
        words = clean_name.split()
        display_name = ' '.join(words[:2]) if len(words) >= 2 else words[0]
        cursor.execute("SELECT id FROM vendors_details WHERE company_name = ?", (clean_name,))
        existing_vendor = cursor.fetchone()
        if not existing_vendor:

            cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
            max_client_code_row = cursor.fetchone()

            if max_client_code_row:
                max_client_code = max_client_code_row[0]
                numeric_part = int(max_client_code.split('-')[-1])
                new_numeric_part = numeric_part + 1
            else:
                new_numeric_part = 1  
            new_vendor_code = f'V - {new_numeric_part:04d}'
            cursor.execute("INSERT INTO vendors_details (vendor_code, company_name, display_name) VALUES (?, ?, ?)", (new_vendor_code,clean_name,display_name))

    db.commit()

    query = """ SELECT name FROM admin_user WHERE department_code = 1000 """
    cursor.execute(query)
    results = cursor.fetchall()
    if not results:
        employee_emails = []  
    else:
        employee_emails = [row[0] for row in results]  
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    valid_emails = [email for email in employee_emails if re.match(email_regex, email)]

    if valid_emails:
        print("saend calim")
        # Claim_Created_Notification(valid_emails,claim_by,latest_claim_no, to_mail)

    return jsonify({'message': 'Claim submitted successfully.', 'claim_id': latest_claim_no})

@app.route('/overhead_claim', methods=['POST'])
def overhead_claim():
    from datetime import datetime
    import re

    claim_by = get_current_user()['name']
    date = datetime.now().strftime("%Y-%m-%d")

    row_indexs = request.form.getlist('ov_row_index[]')
    categories_codes = request.form.getlist('ov_category_subcategory[]')
    purchase_dates = request.form.getlist('ov_purchase_date[]')
    supplier_names = request.form.getlist('ov_Supplier_name[]')
    item_names = request.form.getlist('ov_item_name[]')
    invoice_numbers = request.form.getlist('ov_invoice_number[]')
    currencies = request.form.getlist('ov_currency[]')
    rates = request.form.getlist('ov_rate[]')
    gst_percents = request.form.getlist('ov_gst_percent[]')
    amounts = request.form.getlist('ov_amount[]')
    gst_values = request.form.getlist('ov_gst_value[]')
    totals = request.form.getlist('ov_total[]')
    files = request.files.getlist('ov_attachment[]')


    footer_total_amount = float(request.form.get('ov_footer_total_amount', '0.00').replace(',', ''))
    footer_total_gst = float(request.form.get('ov_footer_total_gst', '0.00').replace(',', ''))
    footer_total_final = float(request.form.get('ov_footer_total_final', '0.00').replace(',', ''))
    to_mail = request.form.get('ov_footer_total_final', '0.00')
    comments = request.form['ov_comments']

    ex_claim = request.form.get('existingovercalim', '').strip()

    db = get_database()
    cursor = db.cursor()
    current_date = datetime.now().date()
    current_year = datetime.now().year

    # Handle existing claim logic
    if ex_claim:
        # Delete old data
        cursor.execute("DELETE FROM claims WHERE claim_id = ? AND claim_type = 'overhead'", (ex_claim,))
        cursor.execute("DELETE FROM claimed_items WHERE claim_no = ? AND claim_type = 'overhead'", (ex_claim,))
        db.commit()

        # Generate new suffix
        match = re.match(r"(O-\d{2}-\d{4})(?:\((\d+)\))?", ex_claim)
        if match:
            base_claim = match.group(1)
            suffix = match.group(2)
            new_suffix = int(suffix) + 1 if suffix else 1
            latest_claim_no = f"{base_claim}({new_suffix})"
        else:
            latest_claim_no = ex_claim
    
    else:
        # Generate a new claim ID
        cursor.execute('SELECT id FROM claims ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        last_claim_no = result[0] if result else 0
        formatted_claim_no = f"{last_claim_no + 1:04d}"
        latest_claim_no = f"O-{str(current_year)[-2:]}-{formatted_claim_no}"

    # Split category codes and names
    category_codes = []
    category_names = []

    for item in categories_codes:
        if " - " in item:
            code, name = item.split("-", 1)
            category_codes.append(code.strip())
            category_names.append(name.strip())
        else:
            category_codes.append(None)
            category_names.append(item.strip())

    # Insert into `claims` table
    cursor.execute('''INSERT INTO claims (claim_by, claim_id, claim_date, status, comments, amount, gst_value, claim_Total, claim_type,balance)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (claim_by, latest_claim_no, current_date, 'Pending', comments,
                    footer_total_amount, footer_total_gst, footer_total_final, 'overhead', footer_total_final))
    db.commit()

    # Insert into `claimed_items`
    for i in range(len(category_codes)):
        cursor.execute('''INSERT INTO claimed_items (claim_by, projectid, Category, Category_code, date,
                          vendor, itemname, invoice_number, Currency, Rate, gst_percent, amount, gst_value, total,
                          claim_no, claim_type)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (claim_by, 1, category_names[i], category_codes[i], purchase_dates[i], supplier_names[i],
                        item_names[i], invoice_numbers[i], currencies[i], rates[i], gst_percents[i], amounts[i],
                        gst_values[i], totals[i], latest_claim_no, 'overhead'))

        clean_name = supplier_names[i].strip()
        clean_name = supplier_names[i].strip()
        words = clean_name.split()
        display_name = ' '.join(words[:2]) if len(words) >= 2 else words[0]
        cursor.execute("SELECT id FROM vendors_details WHERE company_name = ?", (clean_name,))
        existing_vendor = cursor.fetchone()
        if not existing_vendor:

            cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
            max_client_code_row = cursor.fetchone()

            if max_client_code_row:
                max_client_code = max_client_code_row[0]
                numeric_part = int(max_client_code.split('-')[-1])
                new_numeric_part = numeric_part + 1
            else:
                new_numeric_part = 1  
            new_vendor_code = f'V - {new_numeric_part:04d}'
            cursor.execute("INSERT INTO vendors_details (vendor_code, company_name, display_name) VALUES (?, ?, ?)", (new_vendor_code,clean_name,display_name))

    db.commit()

    query = """ SELECT name FROM admin_user WHERE department_code = 1000 """
    cursor.execute(query)
    results = cursor.fetchall()
    if not results:
        employee_emails = []  
    else:
        employee_emails = [row[0] for row in results]  
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    valid_emails = [email for email in employee_emails if re.match(email_regex, email)]

    if valid_emails:
        print("saend calim")
        # Claim_Created_Notification(valid_emails,claim_by,latest_claim_no, to_mail)


    return jsonify({'message': 'Overhead claim submitted successfully.'})

@app.route('/vechicle_claim', methods=['POST'])
def vechicle_claim():
    from datetime import datetime
    import re

    claim_by = get_current_user()['name']
    date = datetime.now().strftime("%Y-%m-%d")

    # Form data
    row_indexs = request.form.getlist('ve_row_index[]')
    categories_codes = request.form.getlist('ve_category[]')
    print(".....categories_codes.................",categories_codes)
    ve_Vehicle_NOs = request.form.getlist('ve_Vehicle_NO[]')
    purchase_dates = request.form.getlist('ve_purchase_date[]')
    supplier_names = request.form.getlist('ve_Supplier_name[]')
    invoice_numbers = request.form.getlist('ve_invoice_number[]')
    currencies = request.form.getlist('ve_currency[]')
    rates = request.form.getlist('ve_rate[]')
    gst_percents = request.form.getlist('ve_gst_percent[]')
    amounts = request.form.getlist('ve_amount[]')
    gst_values = request.form.getlist('ve_gst_value[]')
    totals = request.form.getlist('ve_total[]')
    files = request.files.getlist('ve_attachment[]')


    footer_total_amount = float(request.form.get('ve_footer_total_amount', '0.00').replace(',', ''))
    footer_total_gst = float(request.form.get('ve_footer_total_gst', '0.00').replace(',', ''))
    footer_total_final = float(request.form.get('ve_footer_total_final', '0.00').replace(',', ''))
    to_mail = request.form.get('ve_footer_total_final', '0.00')
    comments = request.form.get('ve_comments')

    ex_claim = request.form.get('existingvechlecalim', '').strip()



    db = get_database()
    cursor = db.cursor()
    current_date = datetime.now().date()
    current_year = datetime.now().year

    # Handle existing claim logic
    if ex_claim:
        cursor.execute("DELETE FROM claims WHERE claim_id = ? AND claim_type = 'vehicle'", (ex_claim,))
        cursor.execute("DELETE FROM claimed_items WHERE claim_no = ? AND claim_type = 'vehicle'", (ex_claim,))
        db.commit()

        match = re.match(r"(V-\d{2}-\d{4})(?:\((\d+)\))?", ex_claim)
        if match:
            base_claim = match.group(1)
            suffix = match.group(2)
            new_suffix = int(suffix) + 1 if suffix else 1
            latest_claim_no = f"{base_claim}({new_suffix})"
        else:
            latest_claim_no = ex_claim
    else:
        # Generate a new claim ID
        cursor.execute('SELECT id FROM claims ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        last_claim_no = result[0] if result else 0
        formatted_claim_no = f"{last_claim_no + 1:04d}"
        latest_claim_no = f"V-{str(current_year)[-2:]}-{formatted_claim_no}"

    # Insert into claims table
    cursor.execute('''INSERT INTO claims (claim_by, claim_id, claim_date, status, comments, amount, gst_value, claim_Total, claim_type, balance)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (claim_by, latest_claim_no, current_date, 'Pending', comments, footer_total_amount, footer_total_gst, footer_total_final, 'vehicle', footer_total_final ))
    db.commit()


    for i in range(len(categories_codes)):
        subcat = f'{ve_Vehicle_NOs[i]} - {categories_codes[i]}'
        print(".......subcat....",subcat)
        cursor.execute('''INSERT INTO claimed_items (claim_by, projectid, Category,Sub_Category, date, 
                          vendor, itemname, invoice_number, Currency, Rate, gst_percent, amount, gst_value, total,
                          claim_no, claim_type)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (claim_by, 0, 'Vehicle', subcat,purchase_dates[i], supplier_names[i],
                        ve_Vehicle_NOs[i], invoice_numbers[i], currencies[i], rates[i], gst_percents[i],
                        amounts[i], gst_values[i], totals[i], latest_claim_no, 'vehicle'))

        clean_name = supplier_names[i].strip()
        clean_name = supplier_names[i].strip()
        words = clean_name.split()
        display_name = ' '.join(words[:2]) if len(words) >= 2 else words[0]
        cursor.execute("SELECT id FROM vendors_details WHERE company_name = ?", (clean_name,))
        existing_vendor = cursor.fetchone()
        if not existing_vendor:

            cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
            max_client_code_row = cursor.fetchone()

            if max_client_code_row:
                max_client_code = max_client_code_row[0]
                numeric_part = int(max_client_code.split('-')[-1])
                new_numeric_part = numeric_part + 1
            else:
                new_numeric_part = 1  
            new_vendor_code = f'V - {new_numeric_part:04d}'
            cursor.execute("INSERT INTO vendors_details (vendor_code, company_name, display_name) VALUES (?, ?, ?)", (new_vendor_code,clean_name,display_name))


    db.commit()

    query = """ SELECT name FROM admin_user WHERE department_code = 1000 """
    cursor.execute(query)
    results = cursor.fetchall()
    if not results:
        employee_emails = []  
    else:
        employee_emails = [row[0] for row in results]  
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    valid_emails = [email for email in employee_emails if re.match(email_regex, email)]

    if valid_emails:
        print("saend calim")
        # Claim_Created_Notification(valid_emails,claim_by,latest_claim_no, to_mail)

    return jsonify({'message': 'Vehicle claim submitted successfully.'})

@app.route('/get_claim_to_edit/<claim_id>')
def get_claim_to_edit(claim_id):
    db = get_database()
    cursor = db.cursor()
    claim_items = db.execute("SELECT * FROM claimed_items WHERE claim_no = ?", (claim_id,)).fetchall()
    items_list = [dict(row) for row in claim_items]  # Convert Row objects to dictionaries
    return jsonify({
        'claim_id': claim_id,
        'items': items_list
    })

def Claim_Created_Notification(employee_emails, user,latest_claim_no, pr_total_value):
    # Establish connection with SMTP server
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    # Set subject and email body
    subject = f"CES-Claim"
    body = (
        "Test mail please ignore.\n\n"
        f"Dear Sir/Madam,\n\n"
        f"This is to inform you that a new claim has been created by {user}.\n\n"
        f"Claim Number: {latest_claim_no}\n"
        f"Claim Total Value: $ {pr_total_value}\n\n"
        "We kindly request your approval for the Claim at your earliest convenience.\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    # Send email to each recipient in the mail_to_list
    for mail_to in employee_emails:
        # Construct the email for each recipient
        message = MIMEMultipart()
        message['From'] = "cestimesheet67@gmail.com"
        message['To'] = mail_to
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        # Send the email
        s.sendmail("cestimesheet67@gmail.com", mail_to, message.as_string())
    s.quit()

def new_claim_pdf(claim_detials, claim_items, latest_claim_no):
    # Convert sqlite3.Row to dictionary
    if isinstance(claim_detials, sqlite3.Row):
        claim_detials = dict(claim_detials)
    
    if isinstance(claim_items, sqlite3.Row):
        claim_items = dict(claim_items)

    # If data_dict is a list, iterate over the list
    if isinstance(claim_items, list):
        # Assuming each item in the list is a dictionary
        claim_items = [{k: normalize_text(v) for k, v in item.items()} for item in claim_items]
    else:
        # If data_dict is not a list, handle as a dictionary
        claim_items = {k: normalize_text(v) for k, v in claim_items.items()}

    # Normalize text in po_details
    claim_detials = {k: normalize_text(v) for k, v in claim_detials.items()}

    # Create a BytesIO object to save the PDF
    pdf_output = BytesIO()

    # Generate the PDF
    pdf = claim_PDF(claim_detials, claim_items, latest_claim_no)  # Pass the required arguments
    pdf.add_claim_page()  # This opens a new page to start drawing content
    pdf.claim_body()

    # Save the PDF to the BytesIO object directly
    pdf_output.write(pdf.output(dest='S').encode('latin1'))  # Write the output to the BytesIO object
    pdf_output.seek(0)  # Seek to the beginning of the BytesIO object

    return pdf_output  # Return the BytesIO object containing the PDF

def get_claim_details(latest_claim_no):
    db = get_database()
    cursor = db.cursor()

    # Get details for the given latest_claim_no
    cursor.execute('SELECT * FROM claimed_items WHERE claim_no = ?', (latest_claim_no,))
    claim_items = cursor.fetchall()
    from datetime import datetime, timedelta

    if claim_items:
        data_dict = []
        total_sum = 0

        for index, item in enumerate(claim_items):
            amount = float(item[15])  # Ensure these indexes match your database schema
            total_value = float(item[19])
            formatted_amount = "{:,.2f}".format(amount)
            formatted_total_value = "{:,.2f}".format(total_value)

            date_str = str(item[2])  # Get the date string from your item

            if date_str:  # If date_str is not empty
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')  # Parse the string to a datetime object
                formatted_date = date_obj.strftime('%d/%m/%y')  # Format the date to 'DD/MM/YY'
            else:
                formatted_date = 'N/A'  # Or set a default value like 'N/A' or 'Not Provided

            item_dict = {
                'index': str(index + 1),
                'Claim By': str(item[1]),
                'Date': str(formatted_date),
                'Project ID': str(item[3]),
                'Project Name': str(item[4]),
                'Category': str(item[5]),
                'Sub Category': str(item[7]),
                'Item Name': str(item[10]),
                'Currency': str(item[11]),
                'Comments': str(item[12]),
                'Invoice Number': str(item[14]),
                'Amount': formatted_amount,
                'GST Percent': str(item[16]),
                'GST Value': str(item[17]),
                'Total': formatted_total_value,
                'Claim No': str(item[20]),
                'Claim Type': str(item[21])
            }

            data_dict.append(item_dict)
            total_sum += total_value

        # print("Data dict:", data_dict)  # Debugging line to check structure
        return {
            'data_dict': data_dict,
            'total_sum': "{:,.2f}".format(total_sum)
        }

    else:
        return {
            'data_dict': [],
            'total_sum': "0.00"
        }

class claim_PDF(FPDF):

    def __init__(self, claim_detials, claim_items, latest_claim_no, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.claim_detials = claim_detials
        self.data_dict = claim_items
        self.latest_claim_no = latest_claim_no
        self.page_height = 292  # Adjust this value based on your page size

    def claim_header(self):
        self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
        self.rect(2, 2 , 205, 292)

        image_path = os.path.join('static', 'CENTROID Logo.jpg')  # Replace with your actual static path
        self.image(image_path, 145, 5, 50, 8) 

        self.set_font('helvetica', '', 12)
        self.set_xy(2, 5)  # Start text at the leftmost side of the page

        # heading
        self.set_font("helvetica", "B", 10)
        self.cell(0, 6, 'Name', ln=True)
        self.set_xy(15, 5.5)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(2, 12)
        self.cell(0, 6, 'Date', ln=True)
        self.set_xy(15, 12)
        self.cell(0, 6, ':', ln=False)

        self.set_xy(20, 5.5)
        self.set_font("helvetica", "", 10)
        self.cell(10, 6, self.claim_detials['claim_by'], ln=True)
        self.set_xy(20, 12)
        from datetime import datetime, timedelta

        try:
            claim_date = datetime.strptime(self.claim_detials['claim_date'], '%Y-%m-%d')
            formatted_claim_date = claim_date.strftime('%d-%m-%Y')
        except ValueError:
            formatted_claim_date = self.claim_detials['claim_date']  # Fallback if date parsing fails


        self.cell(2, 6, formatted_claim_date, ln=True)

        self.set_xy(85, 10)  # Adjust position of the title (center between details and logo)
        self.set_font('helvetica', 'B', 14)  # Title in bold
        self.cell(0, 10, 'Expense Claims', ln=True)  # Title in the center

        self.line(2, 20, 207, 20)  # Line from x=10 to x=200 at y=40



        # Column widths
        index_width = 10
        date_width = 20
        Project_id_width = 20
        Type_width = 30
        description_width = 80
        amount_width = 30
        gst_value_width = 30
        total_width = 40
        # Item table heading
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 21)
        self.cell(index_width, 6, 'S/N', ln=False)
        # self.line(5 + item_width, 94, 5 + item_width, 265)  # Vertical line

        self.set_xy(13, 21)
        self.cell(date_width, 6, 'Date', ln=False)
        # self.line(15 + part_no_width, 94, 15 + part_no_width, 265)  # Vertical line

        self.set_xy(27, 21)
        self.cell(Project_id_width, 6, 'ProjID', ln=False)
        # self.line(49 + description_width, 94, 49 + description_width, 265)  # Vertical line

        self.set_xy(45, 21)
        self.cell(Type_width, 6, 'Type', ln=False)
        # self.line(135 + uom_width, 94, 135 + uom_width, 265)  # Vertical line

        self.set_xy(88, 21)
        self.cell(description_width, 6, 'Description', ln=False)
        # self.line(140 + qty_width, 94, 140 + qty_width, 265)  # Vertical line

        self.set_xy(151, 21)
        self.cell(amount_width, 6, 'Amount', ln=False)
        # self.line(160 + unit_price_width, 94, 160 + unit_price_width, 265)  # Vertical line

        self.set_xy(172, 21)
        self.cell(gst_value_width, 6, 'GST', ln=False)
        # Optionally add a line at the end if desired
        # self.line(190 + total_price_width, 94, 190 + total_price_width, 265)  # Vertical line 230

        self.set_xy(190, 21)
        self.cell(total_width, 6, 'Total ', ln=False)
        # Optionally add a line at the end if desired
        # self.line(190 + total_price_width, 94, 190 + total_price_width, 265)  # Vertical line 230

        self.line(2, 27, 207, 27)  # Line from x=10 to x=200 at y=27

    def add_claim_page(self):
        self.add_page()
        self.claim_header()
        
    def claim_body(self):
        from datetime import datetime, timedelta

        # Ensure that a page is added before adding content
        if not self.page_no():  # Check if no page has been added yet
            self.add_page()
            self.claim_header()  # Add the header if needed

        # Set initial Y position for items
        initial_y_position = 100  # Starting Y position adjusted
        self.set_y(initial_y_position)  # Move the cursor to the desired starting point

        # Loop through data and print each row
        self.set_font("helvetica", "", 10)

        result = self.data_dict
        self.data_dict = result['data_dict']
        print("..............",result['data_dict'])
        self.total_sum = result['total_sum']


        # print("Data dict before generating PDF:", self.data_dict)

        # Column widths
        index_width = 10
        date_width = 20
        project_id_width = 20
        sub_category_width = 35
        item_name_width = 70
        amount_width = 20
        gst_value_width = 15
        total_width = 20

        # Define the offset for the Y position below the line
        y_offset = 1 # You can change this value as needed

        # Set the initial Y position just below the line using the offset
        initial_y_position = 27 + y_offset  # Adjust the Y position based on y_offset
        self.set_y(initial_y_position)  # Move cursor to the desired starting point


        for index, item in enumerate(self.data_dict):
            current_y = self.get_y()

            # Check if Y exceeds the page limit before starting the row
            if current_y >= 270:
                print("Starting a new page before adding a new row")
                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position  # Reset current Y
                self.set_y(current_y)

            # Print Index
            self.set_font("helvetica", "", 10)
            self.set_xy(2, current_y)
            self.cell(index_width, 6, str(item.get('index', '')), ln=False)

            # Print Date
            self.set_xy(10, current_y)
            self.cell(date_width, 6, item.get('Date', ''), ln=False)

            # Print Project ID
            self.set_xy(28, current_y)
            self.cell(project_id_width, 6, item.get('Project ID', ''), ln=False)

            # Print Sub Category (multi_cell for wrapping)
            self.set_xy(40, current_y)
            sub_category_initial_y = self.get_y()
            self.multi_cell(sub_category_width, 6, item.get('Category', ''), 0, 'L')
            sub_category_height = self.get_y() - sub_category_initial_y

            # Check if Y exceeds the page limit after Sub Category
            if self.get_y() >= 270:
                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position
                self.set_y(current_y)

            # Print Item Name (multi_cell for wrapping)
            self.set_font("helvetica", "", 10)
            self.set_xy(75, current_y)
            item_name_initial_y = self.get_y()
            self.multi_cell(item_name_width, 6, item.get('Item Name', ''), 0, 'L')
            item_name_height = self.get_y() - item_name_initial_y

            # Check if Y exceeds the page limit after Item Name
            if self.get_y() >= 270:
                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position
                self.set_y(current_y)

            # Print Amount (multi_cell for wrapping)
            self.set_font("helvetica", "", 10)
            self.set_xy(80 + item_name_width, current_y)
            amount_initial_y = self.get_y()
            self.multi_cell(amount_width, 6, item.get('Amount', ''), 0, 'R')
            amount_height = self.get_y() - amount_initial_y

            # Check if Y exceeds the page limit after Amount
            if self.get_y() >= 270:

                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position
                self.set_y(current_y)

            # Print GST Value (multi_cell for wrapping)
            self.set_font("helvetica", "", 10)
            self.set_xy(80 + item_name_width + amount_width, current_y)
            gst_value_initial_y = self.get_y()
            self.multi_cell(gst_value_width, 6, item.get('GST Value', ''), 0, 'R')
            gst_value_height = self.get_y() - gst_value_initial_y

            # Check if Y exceeds the page limit after GST Value
            if self.get_y() >= 270:
                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position
                self.set_y(current_y)

            # Print Total (multi_cell for wrapping)
            self.set_font("helvetica", "", 10)
            self.set_xy(80 + item_name_width + amount_width + gst_value_width, current_y)
            total_initial_y = self.get_y()
            self.multi_cell(total_width, 6, item.get('Total', ''), 0, 'R')
            total_height = self.get_y() - total_initial_y

            # Check if Y exceeds the page limit after Total
            if self.get_y() >= 270:
                self.line(0 + index_width, 20, 0 + index_width, 285)  # Vertical line
                self.line(6 + date_width, 20, 6 + date_width, 285)  # Vertical line
                self.line(20 + project_id_width, 20, 20 + project_id_width, 285)  # Vertical line
                self.line(40 + sub_category_width, 20, 40 + sub_category_width, 285)  # Vertical line
                self.line(80 + item_name_width, 20, 80 + item_name_width, 285)  # Vertical line
                self.line(150 + amount_width, 20, 150 + amount_width, 285)  # Vertical line
                self.line(170 + gst_value_width, 20, 170 + gst_value_width, 285)  # Vertical line
                self.line(2, 285, 207, 285)  # items table end line 
                self.add_claim_page()
                self.claim_header()
                current_y = initial_y_position
                self.set_y(current_y)

            # Calculate the maximum height used by this row
            max_height = max(sub_category_height, item_name_height, amount_height, gst_value_height, total_height)
            current_y += max_height

            # Draw a horizontal line after the row
            self.line(2, current_y + 0.5, 207, current_y + 0.5)
            self.set_y(current_y)

        # Draw final vertical and horizontal lines
        self.line(0 + index_width, 20, 0 + index_width, 268)
        self.line(6 + date_width, 20, 6 + date_width, 268)
        self.line(20 + project_id_width, 20, 20 + project_id_width, 268)
        self.line(40 + sub_category_width, 20, 40 + sub_category_width, 268)
        self.line(80 + item_name_width, 20, 80 + item_name_width, 268)
        self.line(150 + amount_width, 20, 150 + amount_width, 268)
        self.line(170 + gst_value_width, 20, 170 + gst_value_width, 268)
        self.line(2, 268, 207, 268)
        self.set_xy(145, 270)
        self.set_font('helvetica', 'B', 10)
        self.cell(200, 6, 'Total Amount (SGD) : $ ', ln=True)
        self.set_xy(185, 270)
        self.cell(200, 6, self.total_sum, ln=True)
    
@app.route('/deleteuserclaim/<int:claimid>', methods=["GET", "POST"])
@login_required
def deleteuserclaim(claimid):   
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        cursor = db.execute("SELECT claim_id FROM claims WHERE id = ?", (claimid,))
        claim_no = cursor.fetchone()[0]
        db.execute('DELETE FROM claimed_items WHERE claim_no = ?', [claim_no])
        db.execute('DELETE FROM claims WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('user_claims'))
    return render_template('user_claims.html', user=user)

@app.route('/print_claim/<claim_id>', methods=['POST'])
@login_required
def print_claim(claim_id):
    # Fetch the claim items for the given claim_id from the database
    db = get_database()
    cursor = db.execute('SELECT * FROM claimed_items WHERE claim_no = ?', (claim_id,))
    claim_items = cursor.fetchall()
    latest_claim_no = claim_id

    # Check if claim items exist
    if not claim_items:
        flash('No items found for this claim', 'error')
        return redirect(url_for('user_claims'))

    # Generate the PDF
    claim_items = get_claim_details(latest_claim_no)
    cursor.execute('SELECT * FROM claims WHERE claim_id = ?', (latest_claim_no,))
    claim_detials = cursor.fetchone()
    claim_pdf_file = new_claim_pdf(claim_detials, claim_items, latest_claim_no)


    if claim_pdf_file:
        db.commit()  # Save changes if any
        # Set appropriate MIME type and download name
        return send_file(claim_pdf_file, mimetype='application/pdf', as_attachment=True, download_name=f"{claim_detials['claim_id']}.pdf")

    else:
        flash("No items found for the selected PO number.")
        return redirect(url_for('user_claims'))

@app.route('/claim_editlist', methods=['GET', 'POST'])
@login_required
def claim_editlist():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    
    if request.method == 'GET':
        claim_no = request.args.get('no')
        cursor = db.execute("SELECT * FROM claimed_items WHERE claim_no = ?", (claim_no,))
        claim_data = cursor.fetchall()
        if claim_no.startswith('P'):
            show = 'project'
            edit = 'prj_Yes'
        elif claim_no.startswith('O'):
            show = 'overhead'
            edit = 'over_Yes'
        elif claim_no.startswith('V'):
            show = 'vehicle'
            edit = 'veh_Yes'
        else:
            show = 'unknown'  # Default value in case it doesn't match any of the cases

        ex_claim = claim_no
        user_access = get_employee_access_control(user['name'])
        user = get_current_user()
        department_code = get_department_code_by_username(user['name'])
        cursor.execute('SELECT DISTINCT itemname FROM claimed_items')
        itemname_suggestions = [row[0] for row in cursor.fetchall()]
        cursor.execute('SELECT Vehicle_number FROM vehicle')
        vehicle_numbers = sorted([row[0] for row in cursor.fetchall()])
        user_access = get_employee_access_control(user['name'])

        query = ''' SELECT id AS id, project_name AS name FROM projects WHERE status != 'Closed' AND id != 5002 UNION ALL SELECT e.EnquiryNumber AS id, e.Name AS name FROM enquiries e LEFT JOIN projects p ON e.EnquiryNumber = p.id
            WHERE e.status != 'Lost'  AND p.id IS NULL ORDER BY id DESC'''

        cursor.execute(query)
        combined_data = cursor.fetchall()
        cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
        latest_gst_value = cursor.fetchone()
        gst = latest_gst_value[0]
        # print("Latest GST Value:",gst )
        # Example usage
        return render_template('admin_templates/profile/prof_claim.html', department_code=department_code, itemname_suggestions=itemname_suggestions, user=user, 
                            ex_claim=ex_claim, edit=edit,claim_data=claim_data,gst=gst, show=show, user_access=user_access,vehicle_numbers=vehicle_numbers, projects=combined_data)

@app.route('/fetch_claim_details/<string:claim_no>', methods=["GET"])
@login_required
def fetch_claim_details(claim_no):
    db = get_database()
    cursor = db.cursor()
    claim_details = cursor.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_no,)).fetchone()
    items = cursor.execute("SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC", (claim_no,)).fetchall()
    if not claim_details:
        return jsonify({'success': False, 'message': 'Claim not found'}), 404  # Add status code for not found

    claim_columns = [col[0] for col in cursor.description]  # Extract column names
    items_list = [dict(zip(claim_columns, item)) for item in items]  # Convert claimed_items rows to dictionaries

    return jsonify({
        'success': True,
        'claim_details': dict(claim_details),
        'items': items_list,
    })

@app.route('/prof_pay', methods=['GET', 'POST'])
def prof_pay():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    if user_access and user_access.get("toggleView_pro_Request_view_all") == 'On':
        query = '''SELECT id FROM projects WHERE status != 'Closed' ORDER BY id DESC;'''
        cursor.execute(query)
    else:
        query = """ SELECT id FROM projects WHERE (pm = ? OR project_members LIKE ?) AND status != 'Closed';"""
        cursor.execute(query, (user['name'], f"%{user['name']}%"))

    project_ids = [row[0] for row in cursor.fetchall()]

    if project_ids:
        placeholders = ','.join('?' for _ in project_ids)
        query = """ 
            SELECT * FROM payment_request
            WHERE created_by = ? OR proj_no IN (%s)
            ORDER BY id DESC;
        """ % placeholders
        cursor.execute(query, (user['name'], *project_ids))
    else:
        query = """ 
            SELECT * FROM payment_request
            WHERE created_by = ?
            ORDER BY id DESC;
        """
        cursor.execute(query, (user['name'],))

    payment_request = cursor.fetchall()


    rows = []

    for pay in payment_request:
        id = pay[0]            # The ID column is at index 0
        pay_number = pay[1]
        invoice_no = pay[2]
        pay_date = pay[3]
        proj_no = pay[4]
        po_number = pay[5]
        status = pay[6]
        created_by = pay[7]
        approved_by = pay[8]
        paid_by = pay[9]
        amount = pay[10]
        invoice_file_name = pay[11]
        paid_date = pay[12]
        approved_date = pay[13]
        overall_total_amount = pay[14]
        Invoice_date = pay[15]
        gst_stat = pay[16]
        gst_value = pay[17]
        supplier_name = pay[18]
        project_name = pay[19]
        Terms = pay[20]
        time_period = pay[21]
        balence = pay[22] if pay[22] is not None else 0.0
        from datetime import datetime, timedelta

        if Invoice_date:
            try:
                invoice_date = datetime.strptime(Invoice_date, "%Y-%m-%d")
                today = datetime.today().date()  # Get current date without time

                if time_period in ['Days', 'Advance']:
                    try:
                        terms_int = int(Terms)  # Ensure Terms is an integer
                        due_date = invoice_date + timedelta(days=terms_int)  # Calculate due date
                        due_days = (due_date.date() - today).days  # Days remaining from today
                    except ValueError:
                        due_date = None
                        due_days = None
                        print("Invalid value for 'Terms', expected an integer.")

                elif time_period == 'COD':  # Payment is due immediately
                    due_date = invoice_date
                    due_days = 0  # Due today

                else:
                    due_date = None
                    due_days = None

                due_date_str = due_date.strftime("%m/%d/%y") if due_date else '0/0/0'

            except ValueError:
                print("Invalid Invoice_date format, expected YYYY-MM-DD.")
                due_date = None
                due_days = None
                due_date_str = '0/0/0'
        
        else:
            due_date = None
            due_days = None
            due_date_str = '0/0/0'

        rows.append({ 'id': id,'pay_number': pay_number, 'invoice_no': invoice_no,  'pay_date': pay_date, 
                     'proj_no': proj_no,'po_number': po_number, 'status': status, 'created_by': created_by, 'amount' : amount,
                    'approved_by': approved_by, 'paid_by': paid_by, 'invoice_file_name' : invoice_file_name,
                    'paid_date' : paid_date, 'approved_date' : approved_date, 'overall_total_amount' :overall_total_amount,
                     'Invoice_date' : Invoice_date,  'gst_stat': gst_stat, 'gst_value' : gst_value, 'supplier_name':supplier_name,
                       'project_name':project_name,'Terms': Terms,'time_period':time_period ,'due_date':due_date_str,
                        'due_days': due_days,'balence': balence,  })

    grouped_df = pd.DataFrame(rows)

    if 'status' in grouped_df.columns:
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3})
        grouped_df = grouped_df.sort_values('status_order')
    
    else:
        # print("The 'status' column is missing from rows.")
        grouped_df['status'] = 'Unknown'  # Add a default status or handle differently
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3}).fillna(0)
        grouped_df = grouped_df.sort_values('status_order')

    return render_template('admin_templates/profile/prof_pay.html',user_access=user_access,grouped_df=grouped_df,user = user,department_code=department_code)

@app.route('/prof_prj', defaults={'project_id': None}, methods=["POST", "GET"])
@app.route('/prof_prj/<int:project_id>', methods=["POST", "GET"])
@login_required
def prof_prj(project_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    db = get_database()  
    cursor = db.cursor()
    cursor.execute("""SELECT id, project_name, po_value, budget, requested_by, approved_status FROM projects_request WHERE requested_by = ? ORDER BY id DESC""", (user['name'],))

    project_requests = cursor.fetchall()
    # Print the fetched data
    show = 'new_prj_req'
    project_details =None
    resources =  None
    stage = None


    if project_id:
        project_details = db.execute("SELECT * FROM projects_request WHERE id = ?", (project_id,)).fetchone()
        resource_details = db.execute("SELECT * FROM request_pmtable WHERE project_id = ?", (project_id,)).fetchall()
        resources = {resource['department_code']: resource['hours'] for resource in resource_details}
        stage = 'edit'

    if request.method == 'POST':

        action = request.form.get('action')  # Get the action from the clicked button
        project_id = request.form.get('project_id', type=int)
        projectId = request.form['projectid']
        client = request.form['client']
        projectName = request.form['projectname']
        startTime = request.form['start_time']
        endTime = request.form['end_time']
        status = request.form['status']
        po_number = request.form['po_number']
        po_value = request.form['po_value']
        pm = request.form['projectmanager']
        budget = request.form['budget']
        billing_address =request.form['billing_address1']
        billing_address2 =request.form['billing_address2']
        billing_address3 =request.form['billing_address3']
        delivery_address = request.form['delivery_address1']
        delivery_address2 = request.form['delivery_address2']
        delivery_address3 = request.form['delivery_address3']
        type = request.form['type']
        selected_members = request.form.get('selected_members', '')
        from datetime import datetime
        current_date = datetime.now().strftime('%Y-%m-%d')  # Format: YYYY-MM-DD
        
        if action == "approve_request":
            resources12 = {}
            for key in request.form:
                if key.isdigit():  # Match numeric keys like '1000', '1001', etc.
                    value = request.form.get(key)
                    resources12[key] = float(value) if value else 0.0  # Convert to float and set 0.0 if empty
            # Insert or update into request_pmtable
            for department_code, hours in resources12.items():
                # Check if a record already exists
                existing_record = db.execute(""" SELECT COUNT(*) FROM request_pmtable WHERE project_id = ? AND department_code = ? """, (projectId, department_code)).fetchone()[0]
                if existing_record:
                    # Update the existing record
                    db.execute(""" UPDATE request_pmtable SET hours = ?, total = ? WHERE project_id = ? AND department_code = ?""", (hours, hours, projectId, department_code))
                else:
                    # Insert a new record
                    db.execute(""" INSERT INTO request_pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?) """, (projectId, department_code, hours, 0.0, hours))

            db.commit()

            app_cal_budget = calculate_budget(resources12)

            db.execute(""" UPDATE projects_request SET  client = ?, project_name = ?, start_time = ?, end_time = ?, status = ?, po_number = ?, po_value = ?, pm = ?, 
               delivery_address = ?, billing_address = ?, budget = ?, type = ?, project_members = ?, approved_status = ?, approved_by = ?, approved_date = ?,
                       billing_address2 = ?,billing_address3 = ?,delivery_address2 = ?,delivery_address3 = ? WHERE id = ? """, 
               (client, projectName, startTime, endTime, status, po_number, po_value, pm,  delivery_address, billing_address, app_cal_budget, type, selected_members, 'Approved',
                user['name'],current_date,billing_address2,billing_address3,delivery_address2,delivery_address3, projectId))
            
            db.commit()
            query = "SELECT name FROM admin_user WHERE department_code = 1000;"
            cursor.execute(query)
            email_ids = [row[0] for row in cursor.fetchall()]
            import re
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            valid_emails = [email for email in email_ids if re.match(email_regex, email)]

            if valid_emails:
                print(".first..projectId.............",projectId)
                # Project_request_approval_Notification(valid_emails, projectId, user['name'])

            show = 'new_prj_req'
            flash('Project approved successfully. Please wait for the admin to create the project.', 'prj_req')
            return redirect(url_for('prof_prj'))

        elif action == "create_project":
            resources12 = {}
            for key in request.form:
                if key.isdigit():  # Match numeric keys like '1000', '1001', etc.
                    value = request.form.get(key)
                    resources12[key] = float(value) if value else 0.0  # Convert to float and set 0.0 if empty
            # Insert or update into request_pmtable
            for department_code, hours in resources12.items():
                # Check if a record already exists
                existing_record = db.execute(""" SELECT COUNT(*) FROM request_pmtable WHERE project_id = ? AND department_code = ? """, (projectId, department_code)).fetchone()[0]
                if existing_record:
                    # Update the existing record
                    db.execute(""" UPDATE request_pmtable SET hours = ?, total = ? WHERE project_id = ? AND department_code = ?""", (hours, hours, projectId, department_code))
                else:
                    # Insert a new record
                    db.execute(""" INSERT INTO request_pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?) """, (projectId, department_code, hours, 0.0, hours))
                
                db.execute("INSERT INTO pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?)", (projectId, department_code, hours, 0.0, hours))
            
            cre_cal_budget = calculate_budget(resources12)
            db.execute("UPDATE projects_request SET approved_status = ?, created_by = ?, created_date = ?  WHERE id = ?", ('Created',user['name'],current_date, projectId))
            db.commit()
            db.execute(""" UPDATE projects_request SET  client = ?, project_name = ?, start_time = ?, end_time = ?, status = ?, po_number = ?, po_value = ?, pm = ?, 
               delivery_address = ?, billing_address = ?, budget = ?, type = ?, project_members = ?, approved_status = ?,
                billing_address2 = ?,billing_address3 = ?,delivery_address2 = ?,delivery_address3 = ? WHERE id = ? """, 
               (client, projectName, startTime, endTime, status, po_number, po_value, pm,  delivery_address, billing_address, cre_cal_budget, type, selected_members,
                 'Created', billing_address2,billing_address3,delivery_address2,delivery_address3, projectId))
            db.execute('''INSERT INTO projects (id, client, project_name, start_time, end_time, pm_status, pe_status, status, po_number, pm, po_value, budget, billing_address, 
                         delivery_address,type, project_members, billing_address2,billing_address3,delivery_address2,delivery_address3
                       ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        [projectId, client, projectName, startTime, endTime, 1, 1, status, po_number, pm, po_value, cre_cal_budget, billing_address, delivery_address, type, 
                         selected_members,billing_address2,billing_address3,delivery_address2,delivery_address3])
            db.commit()
            # Step 1: Fetch project_members and pm from the projects table
            query = "SELECT project_members, pm FROM projects WHERE id = ?;"
            cursor.execute(query, (projectId,))
            result = cursor.fetchone()

            if result:
                project_members, pm = result
                members_set = set(project_members.split(',')) if project_members else set()
                if pm:
                    members_set.add(pm)
                members_set = {member.strip() for member in members_set}
                query = """ SELECT au.name FROM admin_user au WHERE au.username IN ({}) OR au.department_code IN (1000, 10, 20) """.format(','.join(['?'] * len(members_set)))
                cursor.execute(query, list(members_set))
                email_ids = [row[0] for row in cursor.fetchall()]  # Extract the emails from the query result
                import re
                email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                valid_emails = [email for email in email_ids if re.match(email_regex, email)]

                if valid_emails:
                    print("Valid Emails:", valid_emails)
                    # Project_created_by_admin_Notification(valid_emails, pm, members_set, projectId)
            else:
                print(f"No project found with ID {projectId}.")

            show = 'new_prj_req'
            flash('Project Is Created successfully..', 'prj_req')
            return redirect(url_for('prof_prj'))

        elif action == "submit_request":
            # Collect dynamic resource data
            resources1 = {}
            for key in request.form:
                if key.isdigit():  # Match numeric keys like '1000', '1001', etc.
                    value = request.form.get(key)
                    resources1[key] = value if value else 0  # Set to 0 if empty or None

            for department_code, hours in resources1.items():
                cursor.execute("""INSERT INTO request_pmtable (project_id, department_code, hours, added_hours,total ) VALUES (?,?,?,?,?)""",
                                (projectId, department_code, hours, 0.0, hours))

            sub_cal_budget = calculate_budget(resources1)
            user_depart_code = get_department_code_by_username( user['name'])
            if user_depart_code == 1001:
                req_status = "Open"
            elif user_depart_code in [20, 10,1000]:
                req_status = "Approved"
            else:
                req_status = "Open"
                
            db.execute('''INSERT INTO projects_request (id, client, project_name, start_time, end_time, pm_status, pe_status, status, po_number, 
                       pm, po_value, budget,  billing_address, delivery_address, type, project_members,approved_status,requested_by,requested_date,
                       billing_address2,billing_address3,delivery_address2,delivery_address3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        [projectId, client, projectName, startTime, endTime, 1, 1, status, po_number, pm, po_value, sub_cal_budget, billing_address, delivery_address, 
                        type, selected_members,req_status,user['name'], current_date,billing_address2,billing_address3,delivery_address2,delivery_address3])
            db.commit()


            if req_status == "Approved":
                query = """SELECT name FROM admin_user WHERE department_code = 1000 ;"""

                cursor.execute(query, {"req_status": req_status})
                email_ids = [row[0] for row in cursor.fetchall()]
                import re
                email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                valid_emails = [email for email in email_ids if re.match(email_regex, email)]
                if valid_emails:
                    print("...projectId.............",projectId)
                    # Project_request_approval_Notification(valid_emails,projectId, user['name'])
            # SQL query
            else:
                query = """SELECT name FROM admin_user WHERE department_code IN (10, 20) ;"""
                cursor.execute(query, {"req_status": req_status})
                email_ids = [row[0] for row in cursor.fetchall()]
                import re
                email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                valid_emails = [email for email in email_ids if re.match(email_regex, email)]
                if valid_emails:
                    print("Valid Emails..........................:", valid_emails)
                    # Project_creation_request_Notification(valid_emails,projectId, user['name'])

            show = 'new_prj_req'
            flash('Project request submitted successfully. Please wait for admin approval.', 'prj_req')

            return redirect(url_for('prof_prj'))

        elif action == "update_request":
            resources12 = {}
            for key in request.form:
                if key.isdigit():  # Match numeric keys like '1000', '1001', etc.
                    value = request.form.get(key)
                    resources12[key] = float(value) if value else 0.0  # Convert to float and set 0.0 if empty
            for department_code, hours in resources12.items():
                existing_record = db.execute(""" SELECT COUNT(*) FROM request_pmtable WHERE project_id = ? AND department_code = ? """, (projectId, department_code)).fetchone()[0]
                if existing_record:
                    db.execute(""" UPDATE request_pmtable SET hours = ?, total = ? WHERE project_id = ? AND department_code = ?""", (hours, hours, projectId, department_code))
                else:
                    # Insert a new record
                    db.execute(""" INSERT INTO request_pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?) """, (projectId, department_code, hours, 0.0, hours))

            db.commit()

            up_cal_budget = calculate_budget(resources12)
            db.execute(""" UPDATE projects_request SET  client = ?, project_name = ?, start_time = ?, end_time = ?, status = ?, po_number = ?, po_value = ?, pm = ?, 
               delivery_address = ?, billing_address = ?, budget = ?, type = ?, project_members = ?,
                billing_address2 = ?,billing_address3 = ?,delivery_address2 = ?,delivery_address3 = ? WHERE id = ? """, 
               (client, projectName, startTime, endTime, status, po_number, po_value, pm,  delivery_address, billing_address, up_cal_budget, type, selected_members,
                billing_address2,billing_address3,delivery_address2,delivery_address3,projectId))
            db.commit()
            show = 'new_prj_req'
            flash('Project Updated successfully.', 'prj_req')
            return redirect(url_for('prof_prj'))

    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    teamlist1 = [row[0] for row in cursor.fetchall()]
    teamlist = sorted(teamlist1, key=lambda x: x.lower())
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    pmlist1 = [row[0] for row in cursor.fetchall()]
    pmlist = sorted(pmlist1, key=lambda x: x.lower())
    cursor.execute('''SELECT EnquiryNumber FROM enquiries WHERE status = 'Won' AND EnquiryNumber NOT IN (SELECT id FROM projects_request) 
                   AND EnquiryNumber NOT IN (SELECT id FROM projects) ORDER BY EnquiryNumber DESC ''')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    user_access = get_employee_access_control(user['name'])
    query = """SELECT COALESCE(COUNT(*), 0) FROM projects_request WHERE approved_status != 'Created'   AND approved_status IS NOT NULL  AND requested_by = ?;"""
    params = (user['name'],)
    cursor.execute(query, params)
    pending_req = cursor.fetchone()[0]  # Get the first element from the result tuple
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/profile/prof_prj.html',user_access=user_access,department_code=department_code,user=user,usernames=usernames,show=show,
                          stage=stage,project_ids=project_ids, pmlist=pmlist,teamlist=teamlist,project_requests=project_requests,project=project_details, resources=resources,
                          pending_req=pending_req, csrf_token=request.form.get('csrf_token'))

@app.route('/prof_do', methods=['GET', 'POST'])
def prof_do():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    if user_access and user_access.get("toggleViewallDO") == 'On':
        cursor = db.execute('SELECT * FROM created_do  ORDER BY id DESC')
        created_do = cursor.fetchall()
    else:
        cursor = db.execute('SELECT * FROM created_do WHERE created_by = ? ORDER BY id DESC',(user['name'],))
        created_do = cursor.fetchall()

    proj_ids = db.execute('SELECT id FROM projects WHERE project_members LIKE ? AND status != "Closed"', ('%' + user['name'] + '%',))

    # Extract IDs into a list
    project_ids = [row['id'] for row in proj_ids]

    rows = []

    for pr in created_do:
        do_number = pr [1]
        do_date = pr [2]
        proj_no= pr [3]
        client = pr [4]
        client_add_l1 = pr [5]
        client_add_l2 = pr [6]
        client_add_l2 = pr [6]
        client_add_l3 = pr [7]
        delivery = pr [8]
        delivery_add_l1 = pr [9]
        delivery_add_l2 = pr [10]
        delivery_add_l3 = pr [11]
        po_number = pr [12]
        status = pr [13]
        created_by = pr [14]
        Project_Ref = pr [15]
        Attn = pr [16]
        Remarks = pr [17]


        cursor.execute('''SELECT item_name, qty, Unit, status, id FROM do_items WHERE do_number = ?''', (do_number,))
        items = cursor.fetchall()
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'item_name': item[0], 'qty': item[1], 
                                'Unit_Price': item[2], 'status' : item[4], 'id': item[4] })


        # Append the main row to the rows list
        rows.append({ 'do_number': do_number,'do_date': do_date, 'proj_no': proj_no, 
                     'client': client, 'client_add_l1': client_add_l1,'client_add_l2': client_add_l2, 'client_add_l3':client_add_l3,
                     'delivery': delivery, 'delivery_add_l1': delivery_add_l1, 'delivery_add_l2' : delivery_add_l2,'delivery_add_l3':delivery_add_l3,
                     'po_number': po_number, 'status': status, 'created_by' : created_by,
                       'Project_Ref': Project_Ref, 'Attn': Attn, 'Sub_DF': pd.DataFrame(sub_df_data) })
    
    grouped_df = pd.DataFrame(rows)

    return render_template('admin_templates/profile/prof_do.html', department_code=department_code,grouped_df=grouped_df,
                        project_ids=project_ids,user_access=user_access, user=user)

@app.route('/get_do_details_to_prof/<string:do_no>', methods=["GET"])
@login_required
def get_do_details_to_prof(do_no):
    db = get_database()
    cursor = db.cursor()

    # Fetch DO details
    do_details = cursor.execute("SELECT * FROM created_do WHERE do_number = ?", (do_no,)).fetchone()
    if not do_details:
        return jsonify({'success': False, 'message': 'DO not found'}), 404  # Return 404 status if not found

    # Fetch DO items
    items = cursor.execute("SELECT * FROM do_items WHERE do_number = ? ORDER BY id DESC", (do_no,)).fetchall()

    # Extract column names before fetching items
    claim_columns = [desc[0] for desc in cursor.description]  # Get column names

    # Convert items into a list of dictionaries
    items_list = [dict(zip(claim_columns, item)) for item in items]

    return jsonify({
        'success': True,
        'do_details': dict(do_details),
        'items': items_list,
    })

@app.route('/prof_time', methods=['GET', 'POST'])
def prof_time():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    show = 'project'
    from datetime import datetime, timedelta

    if request.method == 'POST':

        submit_type = request.form.get('submit')

        if submit_type == 'project_hours':

            try:
                employee_ids = request.form.getlist('employee_id[]')
                department_codes = request.form.getlist('department_code[]')
                project_ids = request.form.getlist('project_id[]')
                project_names = request.form.getlist('project_name[]')
                clients = request.form.getlist('client[]')
                dates = request.form.getlist('date[]')
                hours = request.form.getlist('normal[]')
                overhead1s = request.form.getlist('overhead1[]')
                overhead2s = request.form.getlist('overhead2[]')
                totals = request.form.getlist('total[]')
                section_code = 4000
                success_count = 0  # Count of successfully inserted rows
                error_rows = []    # List to track rows that were skipped due to exceeding 24 hours

                for i in range(len(employee_ids)):
                    employee_id = employee_ids[i]
                    department_code = department_codes[i]
                    project_id = project_ids[i]
                    project_name = project_names[i]
                    client = clients[i]
                    working_date = dates[i]
                    total = totals[i]
                    hours_worked = float(hours[i]) if hours[i] else 0.0
                    overhead1 = float(overhead1s[i]) if overhead1s[i] else 0.0
                    overhead2 = float(overhead2s[i]) if overhead2s[i] else 0.0
                    total_cost = round(hours_worked + (overhead1 * 1.5) + (overhead2 * 2.0), 2)

                    formatted_date = datetime.strptime(working_date, '%Y-%m-%d').date()
                    working_date = formatted_date.strftime('%d %m %Y')

                    # Check if total working hours for the employee exceed 24 hours on the same date
                    cursor.execute(''' SELECT SUM(total_cost)  FROM workingHours  WHERE employeeID = ? AND formatted_date = ? ''', (employee_id, formatted_date))
                    total_existing_hours = cursor.fetchone()[0] or 0.0

                    if total_existing_hours + total_cost > 24.0:
                        error_rows.append((employee_id, working_date, total_existing_hours + total_cost))
                        continue  # Skip this row

                    # Insert the data into the table
                    cursor.execute('''  INSERT INTO workingHours  (section_code, projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, 
                        client, formatted_date, overtime_1_5, overtime_2_0, totalhours, total_cost)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''', (
                        section_code, project_id, department_code, employee_id, working_date, hours_worked,
                        project_name, client, formatted_date, overhead1, overhead2, total, total_cost  ))
                    success_count += 1

                # Commit changes to the database
                db.commit()
                print("..error_rows........",error_rows)

                # Construct flash message
                if success_count > 0:
                    flash_message = f"Successfully recorded {success_count} working hour entries."
                else:
                    flash_message = "No working hour entries were recorded."

                if error_rows:
                    error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)"  for emp, date, hours in error_rows])
                    flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

                flash(flash_message, 'timesheet')
                show = 'project'

            except BadRequest as e:
                flash(f"Error submitting form: {str(e)}", 'pr_claim1')
                db.rollback()
            
            return redirect(url_for('prof_time'))

        if submit_type == 'estimation_hours':

            try:
                employee_ids = request.form.getlist('estemployee_id[]')
                department_codes = request.form.getlist('est_department_code[]')
                enq_ids = request.form.getlist('enq_id[]')
                enq_names = request.form.getlist('enq_name[]')
                enq_clients = request.form.getlist('enq_client[]')
                dates = request.form.getlist('enq_date[]')
                hours = request.form.getlist('enq_hours[]')
                section_code = 5000
                success_count = 0 
                error_rows = []   


                for i in range(len(employee_ids)):
                    employee_id = employee_ids[i]
                    department_code = department_codes[i]
                    enq_id = enq_ids[i]
                    enq_name = enq_names[i]
                    enq_client = enq_clients[i]
                    working_date = dates[i]
                    formatted_date = datetime.strptime(working_date, '%Y-%m-%d').date()
                    working_date = formatted_date.strftime('%d %m %Y')
                    hours_worked = float(hours[i]) if hours[i] else 0.0
                    total = hours_worked
                    overhead1 =  0.0
                    overhead2 =  0.0
                    total_cost = round(hours_worked + (overhead1 * 1.5) + (overhead2 * 2.0), 2)

                    cursor.execute(''' SELECT SUM(total_cost)  FROM workingHours  WHERE employeeID = ? AND formatted_date = ? ''', (employee_id, formatted_date))
                    total_existing_hours = cursor.fetchone()[0] or 0.0

                    if total_existing_hours + total_cost > 24.0:
                        error_rows.append((employee_id, working_date, total_existing_hours + total_cost))
                        continue  # Skip this row
                    # print("new_formatted_date..............",working_date)
                    # print("formatted_date..............",formatted_date)
                    cursor.execute(''' INSERT INTO workingHours (section_code, projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, 
                                   client, formatted_date, overtime_1_5, overtime_2_0, totalhours, total_cost) VALUES (?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                                   ( section_code, enq_id,department_code,employee_id, working_date, hours_worked, enq_name, enq_client, formatted_date,
                                    overhead1,overhead2,total,total_cost ))
                    success_count += 1

                db.commit()


                if success_count > 0:
                    flash_message = f"Successfully recorded {success_count} working hour entries."
                else:
                    flash_message = "No working hour entries were recorded."

                if error_rows:
                    error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)"  for emp, date, hours in error_rows])
                    flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

                flash(flash_message, 'estimation_time')

                # flash('Your working hours have been recorded successfully.', 'estimation_time')
                show = 'estimation'

            except BadRequest as e:
                flash(f"Error submitting form: {str(e)}", 'pr_claim1')
                db.rollback()
            
            return redirect(url_for('prof_time'))

        if submit_type == 'overhead_hours':

            try:
                employee_ids = request.form.getlist('ovremployee_id[]')
                department_codes = request.form.getlist('ovr_department_code[]')
                dates = request.form.getlist('ovr_date[]')
                hours = request.form.getlist('ovr_hours[]')
                section_code = 5001
                success_count = 0 
                error_rows = []   
                #print("...............employee_ids........................",employee_ids)


                for i in range(len(employee_ids)):
                    employee_id = employee_ids[i]
                    department_code = department_codes[i]
                    working_date = dates[i]
                    hours_worked = float(hours[i]) if hours[i] else 0.0
                    formatted_date = datetime.strptime(working_date, '%Y-%m-%d').date()
                    working_date = formatted_date.strftime('%d %m %Y')
                    total = hours_worked
                    overhead1 =  0.0
                    overhead2 =  0.0
                    total_cost = round(hours_worked + (overhead1 * 1.5) + (overhead2 * 2.0), 2)

                                        # Check if total working hours for the employee exceed 24 hours on the same date
                    cursor.execute(''' SELECT SUM(total_cost)  FROM workingHours  WHERE employeeID = ? AND formatted_date = ? ''', (employee_id, formatted_date))
                    total_existing_hours = cursor.fetchone()[0] or 0.0

                    if total_existing_hours + total_cost > 24.0:
                        error_rows.append((employee_id, working_date, total_existing_hours + total_cost))
                        continue  # Skip this row

                    cursor.execute(''' INSERT INTO workingHours (section_code, departmentID, employeeID, workingDate, hoursWorked, formatted_date,overtime_1_5, overtime_2_0, totalhours, total_cost) VALUES 
                                   (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    ( section_code,department_code,employee_id, working_date, hours_worked, formatted_date, overhead1,overhead2,total,total_cost ))
                    success_count += 1
                db.commit()

                print("..error_rows........",error_rows)

                # Construct flash message
                if success_count > 0:
                    flash_message = f"Successfully recorded {success_count} working hour entries."
                else:
                    flash_message = "No working hour entries were recorded."

                if error_rows:
                    error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)"  for emp, date, hours in error_rows])
                    flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

                flash(flash_message, 'overhead_time')
                
                # flash('Your working hours have been recorded successfully.', 'overhead_time')
                show = 'overhead_time'

            except BadRequest as e:
                flash(f"Error submitting form: {str(e)}", 'pr_claim1')
                db.rollback()

            return redirect(url_for('prof_time'))
        
        if submit_type == 'service_hours':

            try:
                employee_ids = request.form.getlist('seremployee_id[]')
                department_codes = request.form.getlist('ser_department_code[]')
                project_names = request.form.getlist('ser_site[]')
                clients = request.form.getlist('ser_client[]')
                dates = request.form.getlist('ser_date[]')
                hours = request.form.getlist('ser_normal[]')
                ser_overhead1s = request.form.getlist('ser_overhead1[]')
                ser_overhead2s = request.form.getlist('ser_overhead2[]')
                ser_totals = request.form.getlist('ser_total[]')

                section_code = 5002
                #print("...............employee_ids........................",employee_ids)
                success_count = 0 
                error_rows = [] 


                for i in range(len(employee_ids)):
                    print(i)
                    employee_id = employee_ids[i]
                    department_code = department_codes[i]
                    project_name = project_names[i]
                    client = clients[i]
                    working_date = dates[i]
                    ser_total = ser_totals[i]
                    hours_worked = float(hours[i]) if hours[i] else 0.0
                    ser_overhead1 = float(ser_overhead1s[i]) if ser_overhead1s[i] else 0.0
                    ser_overhead2 = float(ser_overhead2s[i]) if ser_overhead2s[i] else 0.0
                    total_cost = round(hours_worked + (ser_overhead1 * 1.5) + (ser_overhead2 * 2.0), 2)
                    formatted_date = datetime.strptime(working_date, '%Y-%m-%d').date()
                    working_date = formatted_date.strftime('%d %m %Y')
                    # Check if total working hours for the employee exceed 24 hours on the same date
                    cursor.execute(''' SELECT SUM(total_cost)  FROM workingHours  WHERE employeeID = ? AND formatted_date = ? ''', (employee_id, formatted_date))
                    total_existing_hours = cursor.fetchone()[0] or 0.0

                    if total_existing_hours + total_cost > 24.0:
                        error_rows.append((employee_id, working_date, total_existing_hours + total_cost))
                        continue  # Skip this row

                    cursor.execute(''' INSERT INTO workingHours (section_code, departmentID, employeeID, workingDate, hoursWorked, project_name, 
                                   client, formatted_date, overtime_1_5, overtime_2_0, totalhours, total_cost) VALUES (?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?)''', 
                                   ( section_code,department_code,employee_id, working_date, hours_worked, project_name, client, formatted_date,
                                    ser_overhead1,ser_overhead2,ser_total,total_cost ))
                    success_count += 1
                db.commit()
                print("..error_rows........",error_rows)

                # Construct flash message
                if success_count > 0:
                    flash_message = f"Successfully recorded {success_count} working hour entries."
                else:
                    flash_message = "No working hour entries were recorded."

                if error_rows:
                    error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)"  for emp, date, hours in error_rows])
                    flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

                flash(flash_message, 'service_time')
                show = 'service_time'

            except BadRequest as e:
                flash(f"Error submitting form: {str(e)}", 'pr_claim1')
                db.rollback()

            return redirect(url_for('prof_time'))

        if submit_type == 'Warranty_hours':

            try:
                employee_ids = request.form.getlist('war_employee_id[]')
                department_codes = request.form.getlist('war_department_code[]')
                enq_ids = request.form.getlist('war_project_id[]')
                enq_names = request.form.getlist('war_project_name[]')
                enq_clients = request.form.getlist('war_client[]')
                dates = request.form.getlist('war_date[]')
                hours = request.form.getlist('war_normal[]')
                war_overhead1s = request.form.getlist('war_overhead1[]')
                war_overhead2s = request.form.getlist('war_overhead2[]')
                war_totals = request.form.getlist('war_total[]')
                section_code = 5003
                success_count = 0 
                error_rows = [] 
                #print("...............employee_ids........................",employee_ids)


                for i in range(len(employee_ids)):
                    employee_id = employee_ids[i]
                    department_code = department_codes[i]
                    enq_id = enq_ids[i]
                    enq_name = enq_names[i]
                    enq_client = enq_clients[i]
                    working_date = dates[i]
                    war_total = war_totals[i]
                    hours_worked = float(hours[i]) if hours[i] else 0.0
                    war_overhead1 = float(war_overhead1s[i]) if war_overhead1s[i] else 0.0
                    war_overhead2 = float(war_overhead2s[i]) if war_overhead2s[i] else 0.0
                    total_cost = round(hours_worked + (war_overhead1 * 1.5) + (war_overhead2 * 2.0), 2)

                    formatted_date = datetime.strptime(working_date, '%Y-%m-%d').date()
                    working_date = formatted_date.strftime('%d %m %Y')

                    # Check if total working hours for the employee exceed 24 hours on the same date
                    cursor.execute(''' SELECT SUM(total_cost)  FROM workingHours  WHERE employeeID = ? AND formatted_date = ? ''', (employee_id, formatted_date))
                    total_existing_hours = cursor.fetchone()[0] or 0.0

                    if total_existing_hours + total_cost > 24.0:
                        error_rows.append((employee_id, working_date, total_existing_hours + total_cost))
                        continue  # Skip this row

                    cursor.execute(''' INSERT INTO workingHours (section_code, projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, 
                                   client, formatted_date, overtime_1_5, overtime_2_0, totalhours, total_cost ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                                   ( section_code, enq_id,department_code,employee_id, working_date, hours_worked, enq_name, enq_client, formatted_date,
                                    war_overhead1,war_overhead2,war_total,total_cost ))
                    success_count += 1
                db.commit()
                print("..error_rows........",error_rows)

                # Construct flash message
                if success_count > 0:
                    flash_message = f"Successfully recorded {success_count} working hour entries."
                else:
                    flash_message = "No working hour entries were recorded."

                if error_rows:
                    error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)"  for emp, date, hours in error_rows])
                    flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

                flash(flash_message, 'Warranty_time')

                show = 'Warranty_time'

            except BadRequest as e:
                flash(f"Error submitting form: {str(e)}", 'pr_claim1')
                db.rollback()

            return redirect(url_for('prof_time'))

    allowed_departments = get_allowed_departments(department_code, user['name'])

    if len(allowed_departments) == 1 and allowed_departments[0] == user['name']:
        usernames = [user['name']]
   
    else:
        placeholders = ','.join('?' for _ in allowed_departments)
        query = f'SELECT username FROM admin_user WHERE department_code IN ({placeholders})'
        cursor.execute(query, allowed_departments)
        usernames1 = [row[0] for row in cursor.fetchall()]
        usernames = sorted(usernames1, key=lambda x: x.lower()) 
        if user['name'] not in usernames:
            usernames.append(user['name'])

    cursor.execute('''SELECT id, project_name FROM projects WHERE status <> 'Closed' ORDER BY id DESC;''')
    projects = cursor.fetchall()
    cursor.execute('SELECT EnquiryNumber, Name FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = cursor.fetchall()
    return render_template('admin_templates/profile/prof_time.html', projects=projects,enq_ids=enq_ids,user=user,department_code=department_code,
                          show=show,usernames=usernames,user_access=user_access)

@app.route('/prof_act', methods=['GET', 'POST'])
def prof_act():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    EmployeeID = user['name']
    optionValue = 'dashboard'
    dashboard_data= { }


    if request.method == 'POST':

        action = request.form.get('action')

        if action == 'apply_leave':
            # print("..............inside post............")
            from dateutil import parser

            try:
                leave_type = request.form.get('leave_type')
                lev_startdate = request.form.get('start_date')
                lev_enddate = request.form.get('end_date')
                employee_id = request.form.get('Received_by')
                from datetime import datetime, timedelta

                # print("...............employee_ids........................", employee_id)
                # print("...............leave_type........................", leave_type)
                # print("...............lev_startdate........................", lev_startdate)
                # print("...............lev_enddate........................", lev_enddate)

                # Convert the input dates to datetime objects
                lev_startdate = datetime.strptime(lev_startdate, '%Y-%m-%d')
                lev_enddate = datetime.strptime(lev_enddate, '%Y-%m-%d')

                # Retrieve leave allocation data for the employee for the current year
                cursor.execute("""SELECT Start_Date, Annual FROM admin_leave_allocation WHERE EmployeeID = ? AND Year = ?""", (employee_id, datetime.now().year))
                temp = cursor.fetchone()
                # print("......temp............", temp)

                # Default values if no record found
                if temp is None:
                    join_date_str = datetime.now().strftime("%Y-%m-%d")  # Default to current date if no record exists
                    annual_leave_entitlement = 0  # Default entitlement to zero
                    print("No record found. Setting join date to current date and annual leave to zero.")
                else:
                    join_date_str = temp["Start_Date"]
                    annual_leave_entitlement = temp["Annual"]

                # Calculate pro-rated annual leave based on employee's joining date
                if join_date_str:
                    join_date = datetime.strptime(join_date_str, "%Y-%m-%d")
                    current_date = datetime.now()

                    # Calculate the number of complete 30-day periods since joining
                    days_since_joining = (current_date - join_date).days
                    completed_30_day_periods = days_since_joining // 30  # Full 30-day periods

                    # Pro-rate the annual leave entitlement
                    annual_leave_entitlement_per_30_days = annual_leave_entitlement / 12  # Monthly leave
                    total_pro_rated_annual_leave = completed_30_day_periods * annual_leave_entitlement_per_30_days

                    # Round the pro-rated leave to 2 decimal places
                    allocation = {
                        "Medical": round(total_pro_rated_annual_leave, 2),
                        "Annual": round(total_pro_rated_annual_leave, 2),
                        "Maternity": round(total_pro_rated_annual_leave, 2),
                        "Paternity": round(total_pro_rated_annual_leave, 2),
                        "Unpaid": -1  # Unpaid leave has no limit
                    }

                # Check if leave overlaps with previous leave requests
                temp_check_leave_overlap = check_leave_overlap(employee_id, lev_startdate, lev_enddate)
                if not temp_check_leave_overlap:
                    # Calculate the number of used leave days for this employee and leave type
                    used_days_query = """SELECT COUNT(*) AS used_days FROM leaves WHERE employeeID = ? AND leave_type = ? AND status = 'Approved'"""
                    cursor.execute(used_days_query, (employee_id, leave_type))
                    used_days_result = cursor.fetchone()
                    used_days = used_days_result['used_days'] if used_days_result else 0
                    # print("....used_days..........", used_days)

                    # Calculate the total number of days requested for the leave, excluding weekends and public holidays
                    current_date = lev_startdate
                    public_holidays = set()
                    cursor.execute('SELECT date FROM public_holidays')
                    public_holidays_data = cursor.fetchall()
                    for holiday in public_holidays_data:
                        public_holidays.add(parser.parse(holiday['date']).date())

                    calculated_number_of_days = 0
                    while current_date <= lev_enddate:
                        if current_date.weekday() not in (5, 6) and current_date.date() not in public_holidays:  # Exclude weekends and public holidays
                            calculated_number_of_days += 1
                        current_date += timedelta(days=1)
                    # print("....calculated_number_of_days.........", calculated_number_of_days)

                    # Check if the requested leave exceeds the eligible leave
                    if leave_type == 'Unpaid':
                        leaves_left = -1  # No limit for unpaid leave
                    else:
                        eligible_days = allocation.get(leave_type, 0)  # Get the pro-rated leave for the given type
                        leaves_left = (used_days + calculated_number_of_days) - eligible_days
                    # print("-----------------------leaves_left------------------", leaves_left)

                    # Prepare the SQL query
                    regquery = 'SELECT register FROM admin_user WHERE username = ?'

                    # Execute the query with the employee_id parameter
                    cursor.execute(regquery, (employee_id,))

                    # Fetch the result
                    regvalue = cursor.fetchone()

                    if leaves_left > 0 and regvalue == 1:
                        return jsonify(success=False, message=f"Exceeded {leave_type} leave by {leaves_left} days. Used: {used_days}, Eligible: {eligible_days}. Please consider unpaid leave for excess days.")
                        # flash(f"Exceeded {leave_type} leave by {leaves_left} days. Used: {used_days}, Eligible: {eligible_days}. Please consider unpaid leave for excess days.", 'profile_leave1')
                    else:
                        # Format the dates if necessary
                        formatted_startdate = lev_startdate.strftime('%Y-%m-%d')
                        formatted_enddate = lev_enddate.strftime('%Y-%m-%d')
                        calculated_number_of_days = f"{calculated_number_of_days} Days"

                        # Insert leave details into `leaves_approved` table
                        db.execute('INSERT INTO leaves_approved (employeeID, leave_type, start_date, end_date, number_of_days, status) VALUES (?, ?, ?, ?, ?, ?)',
                                (employee_id, leave_type, formatted_startdate, formatted_enddate, calculated_number_of_days, 'Pending'))
                        db.commit()

                        # flash(f'Your {leave_type} leave of {calculated_number_of_days} has been recorded successfully. Please wait for approval.', 'profile_leave')
                        return jsonify(success=True, message=f'Your {leave_type} leave of {calculated_number_of_days} has been recorded successfully. Please wait for approval.')
                else:
                    # flash("You have already applied for this date. Cannot proceed. Please check your leave history", 'profile_leave1')
                    return jsonify(success=False, message="You have already applied for this date. Cannot proceed. Please check your leave history")


            except BadRequest as e:
                return jsonify(success=False, message=f"Error submitting form: {str(e)}")
                flash(f"Error submitting form: {str(e)}", 'profile_leave1')
                db.rollback()
                # return jsonify(success=False)

            optionValue = 'leave_time'

    # Fetch attended courses for the employee
    cursor.execute("SELECT * FROM attended_courses WHERE Employee_ID = ?", (EmployeeID,))
    courses_data = cursor.fetchall()

    from datetime import datetime, timedelta
    courses = []

    for row in courses_data:
        course = { "ID": row[0], "Name": row[1], "Course_Name": row[2], "Date_Attained": row[3], "Expiry_Date": row[4] }

        # Check if Date_Attained is not empty
        if course['Date_Attained']:
            date_attained = datetime.strptime(course['Date_Attained'], "%Y-%m-%d")
        else:
            date_attained = None  # Or handle accordingly, like setting a default date

        # Check if Expiry_Date is not empty
        if course['Expiry_Date']:
            expiry_date = datetime.strptime(course['Expiry_Date'], "%Y-%m-%d")
        else:
            expiry_date = None  # Or handle accordingly, like setting a default date

        # Calculate days left if expiry_date is not None
        if expiry_date:
            days_left = (expiry_date - datetime.now()).days
        else:
            days_left = None  # Handle if expiry_date is missing

        # Add the days left to the course dictionary
        course['Days_Left'] = days_left

        courses.append(course)

    # Fetch issued assets for the employee
    cursor.execute("SELECT * FROM issued_assets WHERE Employee_ID = ?", (EmployeeID,))
    assets = cursor.fetchall()

    one_month_ago = datetime.now() - timedelta(days=30)
    cursor.execute("""SELECT section_code, projectID, totalhours, formatted_date FROM workingHours WHERE employeeID = ? AND formatted_date >= ?""",  (user['name'], one_month_ago.strftime('%Y-%m-%d')))
    results = cursor.fetchall()
    data = []

    for row in results:
        entry = { 'section_code': row[0], 'projectID': row[1], 'totalhours': row[2], 'formatted_date': row[3] }
        data.append(entry)

    if data:
        df = pd.DataFrame(data)
        # Convert 'formatted_date' to datetime
        df['formatted_date'] = pd.to_datetime(df['formatted_date'])
        df['formatted_date'] = df['formatted_date'].dt.strftime('%d-%m-%y')

        # Group by 'formatted_date' and sum the 'hoursWorked'
        df_date_hours = df.groupby('formatted_date')['totalhours'].sum().reset_index()
        # Extract the lists
        dates = df_date_hours['formatted_date'].tolist()
        hours = df_date_hours['totalhours'].tolist()

        # Group by 'projectID' and sum the 'hoursWorked'
        df_project_hours = df.groupby('projectID')['totalhours'].sum().reset_index()
        pro_ids = df_project_hours['projectID'].tolist()
        hours_spent = df_project_hours['totalhours'].tolist()

    else:
        # Handle the case where no data was found
        dates = []
        hours = []
        pro_ids = []
        hours_spent = []


    employee_id = user['name']
    cursor = db.execute('''SELECT * FROM employee_details WHERE display_Name = ?''', (employee_id,))
    emp_data = cursor.fetchone()

    total_projects         = db.execute("SELECT COUNT(DISTINCT projectID) AS projects_involved FROM workingHours WHERE employeeID = ?;", (employee_id,)).fetchone()[0] or 0
    total_hours_worked     = db.execute("SELECT SUM(totalhours) FROM workingHours WHERE employeeID = ?", (employee_id,)).fetchone()[0] or 0
    total_leaves           = db.execute("SELECT COUNT(*) FROM leaves WHERE employeeID = ?", (employee_id,)).fetchone()[0] or 0
    total_courses_attended = db.execute("SELECT COUNT(*) FROM attended_courses WHERE Employee_ID = ?", (employee_id,)).fetchone()[0] or 0
    total_assets_issued    = db.execute("SELECT COUNT(*) FROM issued_assets WHERE Employee_ID = ?", (employee_id,)).fetchone()[0] or 0
    total_enquiries        = db.execute("SELECT COUNT(*) FROM enquiries WHERE client = ?", (employee_id,)).fetchone()[0] or 0

    # Data for charts
    hours_worked_data = db.execute("SELECT workingDate, SUM(totalhours) FROM workingHours WHERE employeeID = ? GROUP BY workingDate", (employee_id,)).fetchall()
    leave_types_data = db.execute("SELECT leave_type, COUNT(*) FROM leaves WHERE employeeID = ? GROUP BY leave_type", (employee_id,)).fetchall()
    claims_status_data = db.execute("SELECT status, COUNT(*) FROM claims WHERE claim_by = ? GROUP BY status", (employee_id,)).fetchall()
    expenses_data = db.execute("SELECT claim_date, SUM(claim_Total) FROM Expenses WHERE claim_by = ? GROUP BY claim_date", (employee_id,)).fetchall()
    course_expiry_data = db.execute("SELECT Course_Name, Expiry_Date FROM attended_courses WHERE Employee_ID = ?", (employee_id,)).fetchall()


    pr_raised = db.execute("SELECT COUNT(*) FROM created_pr WHERE created_by = ?;", (employee_id,)).fetchone()[0] or 0
    po_approved = db.execute("SELECT COUNT(*) FROM created_po WHERE created_by = ?;", (employee_id,)).fetchone()[0] or 0
    Claims_made = db.execute("SELECT COUNT(*) FROM claims WHERE claim_by = ?;", (employee_id,)).fetchone()[0] or 0
    claimed_amount = db.execute("SELECT SUM(claim_Total) AS total_amount FROM claims WHERE claim_by = ?;", (employee_id,)).fetchone()[0] or 0


    # Execute the query
    cursor.execute(""" SELECT  SUM(overtime_1_5) AS total_overtime_1_5, SUM(overtime_2_0) AS total_overtime_2_0 FROM workingHours WHERE employeeID = ?; """, (employee_id,))
    result = cursor.fetchone()

    total_overtime_1_5 = result[0] if result[0] is not None else 0
    total_overtime_2_0 = result[1] if result[1] is not None else 0

    from datetime import datetime, timedelta

    current_date = datetime.now().date()

    # Fetch the last working date for the employee
    cursor.execute("""SELECT formatted_date FROM workingHours WHERE employeeID = ? ORDER BY formatted_date DESC, entryID DESC LIMIT 1;""", (employee_id,))
    last_entry = cursor.fetchone()

    # Handle case where no work hours are recorded
    if not last_entry:
        print(f"No work hours recorded for employee {employee_id}.")
        time_sheet_missing_days_alert = 0  # No missing days to report

    else:
        last_working_date = datetime.strptime(last_entry['formatted_date'], '%Y-%m-%d').date()

        # Fetch current year's public holidays
        current_year = current_date.year
        cursor.execute("""SELECT date FROM public_holidays WHERE strftime('%Y', date) = ?;""", (str(current_year),))
        public_holidays = {datetime.strptime(row['date'], '%Y-%m-%d').date() for row in cursor.fetchall()}

        # Calculate the number of missing days
        missing_days = 0
        check_date = last_working_date + timedelta(days=1)  # Start the day after the last working day

        while check_date <= current_date:
            if check_date.weekday() not in (5, 6) and check_date not in public_holidays:  # Exclude weekends and holidays
                missing_days += 1
            check_date += timedelta(days=1)

        # Set the alert for missing days
        time_sheet_missing_days_alert = missing_days

    dashboard_data.update({
        "pr_raised" : pr_raised,
        "po_approved" : po_approved,
        "Claims_made" : Claims_made,
        "claimed_amount" : claimed_amount,
        "projects_involved" : total_projects,
        "total_hours_worked" : total_hours_worked,
        "total_leaves" : total_leaves,
        "total_courses_attended" : total_courses_attended,
        "total_assets_issued" : total_assets_issued,
        "total_enquiries" : total_enquiries,
        "total_overtime_1_5" : total_overtime_1_5,
        "total_overtime_2_0" : total_overtime_2_0,
        "time_steet_missing_days_alert" : time_sheet_missing_days_alert
    })

    # Formatting data for charts
    hours_worked        = [row[1] for row in hours_worked_data]
    work_dates          = [row[0] for row in hours_worked_data]  # Renamed to avoid conflict
    leave_types         = [row[0] for row in leave_types_data]
    leave_counts        = [row[1] for row in leave_types_data]
    claim_statuses      = [row[0] for row in claims_status_data]
    claim_counts        = [row[1] for row in claims_status_data]
    expense_dates       = [row[0] for row in expenses_data]
    expense_amounts     = [row[1] for row in expenses_data]
    course_names        = [row[0] for row in course_expiry_data]
    course_expiry_dates = [row[1] for row in course_expiry_data]

    # Use employee's name from the user dictionary
    employee_name1 = user['name']

    # Query to get the count of each leave type for the given employee
    leave_type_query = ''' SELECT leave_type, COUNT(*)  FROM leaves  WHERE employeeID = :employee_name GROUP BY leave_type '''
    leave_counts = db.execute(leave_type_query, {'employee_name': employee_name1})


    # Assuming the user's department code is stored in `department_code`
    department_code = get_department_code_by_username(user['name'])
    # Adjust the query based on whether the department code is 1000 or not
    if department_code == 1000:
        # Fetch all usernames if department code is 1000
        cursor.execute("SELECT username FROM admin_user")
        usernames1 = [row[0] for row in cursor.fetchall()]
        usernames = sorted(usernames1, key=lambda x: x.lower())
    
    else:
        # If department code is not 1000, set usernames list as user's name
        cursor.execute('SELECT username FROM admin_user WHERE department_code > ?', (department_code,))
        usernames1 = [row[0] for row in cursor.fetchall()]
        usernames1.append(user['name'])
        usernames = sorted(usernames1, key=lambda x: x.lower())

    user_access = get_employee_access_control(user['name'])

    messages = {
        "expected_in_2_days": "PO #{{po_number}}: Expected delivery in 2 days. Please verify.",
        "expected_in_2_days": "PO #{{po_number}}: Expected delivery in 3 days. Please verify.",
        "expected_today": "PO #{{po_number}}: Expected delivery today. Confirm status.",
        "expected_today": "PO #{{po_number}}: Expected delivery today1. Confirm status.",
        "overdue": "PO #{{po_number}}: Delivery overdue. Check status.",
        "overdue": "PO #{{po_number}}: Delivery overdue. Check status1.",
        "status_open": "PO #{{po_number}}: Status is still open. Take action.",
        "status_open": "PO #{{po_number}}: Status is still open. Take action1."
    }
    query_open = "SELECT PO_no FROM created_po WHERE do_staus = 'Open';"
    cursor.execute(query_open)
    open_pos = [row[0] for row in cursor.fetchall()]

    # Query to fetch PO numbers where do_staus is 'Partial'
    query_partial = "SELECT PO_no FROM created_po WHERE do_staus = 'Partial';"
    cursor.execute(query_partial)
    partial_pos = [row[0] for row in cursor.fetchall()]

    messages = {
        "status_open": [f"PO ({po_number}) Material request status still open. Please take action." for po_number in open_pos],
        "status_partial": [f"PO ({po_number}) is partially delivered. Address pending items." for po_number in partial_pos]
    }

    from datetime import datetime, timedelta
    today = datetime.today().date()
    tomorrow = today + timedelta(days=1)
    day_after_tomorrow = today + timedelta(days=2)

    # Query to get deliveries expected today
    query_today = """ SELECT DISTINCT PO_number FROM po_items WHERE excepted_date = ?;"""
    cursor.execute(query_today, (today,))
    deliveries_today = cursor.fetchall()

    # Query to get deliveries expected in 1 or 2 days
    query_next_2_days = """ SELECT DISTINCT PO_number FROM po_items WHERE excepted_date BETWEEN ? AND ?;"""
    cursor.execute(query_next_2_days, (tomorrow, day_after_tomorrow))
    deliveries_next_2_days = cursor.fetchall()

    # Query to get overdue deliveries
    query_overdue = """ SELECT DISTINCT PO_number FROM po_items WHERE excepted_date < ?;"""
    cursor.execute(query_overdue, (today,))
    overdue_deliveries = cursor.fetchall()

    # Format the messages
    if "deliveries_today" not in messages:
        messages["deliveries_today"] = []
    messages["deliveries_today"].extend(
        [f"PO ({po['PO_number']}): Item delivery expected today." for po in deliveries_today]
    )

    if "deliveries_next_2_days" not in messages:
        messages["deliveries_next_2_days"] = []
    messages["deliveries_next_2_days"].extend(
        [f"PO ({po['PO_number']}): Item delivery due in 1-2 days." for po in deliveries_next_2_days]
    )

    if "overdue_deliveries" not in messages:
        messages["overdue_deliveries"] = []
    messages["overdue_deliveries"].extend(
        [f"PO ({po['PO_number']}): Items delivery overdue. Immediate action required." for po in overdue_deliveries]
    )




    return render_template('admin_templates/profile/prof_act.html', dates=dates, pro_ids=pro_ids, hours_spent=hours_spent, hours=hours, user=user,
                           department_code=department_code, work_dates=work_dates, leave_types=leave_types, leave_counts=leave_counts, claim_statuses=claim_statuses,
                           claim_counts=claim_counts, expense_dates=expense_dates, expense_amounts=expense_amounts,
                           optionValue=optionValue,usernames=usernames,user_access=user_access,course_names=course_names, messages=messages,
                           course_expiry_dates=course_expiry_dates,emp_data=emp_data,courses=courses,assets=assets,dashboard_data=dashboard_data)

@app.route('/prof_suppliers_del', methods=['GET'])
@login_required
def prof_suppliers_del():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    id = request.args.get('id')
    db = get_database()
    db.execute("DELETE FROM vendors_details WHERE id = ?", (id,))
    db.commit()
    
    flash('Client details deleted successfully', 'success')
    return redirect(url_for('prof_supplier'))

@app.route('/prof_supplier', methods=['GET', 'POST'])
def prof_supplier():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM vendors_details ORDER BY id DESC')
    vendors = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
    max_client_code_row = cursor.fetchone()

    if max_client_code_row:
        max_client_code = max_client_code_row[0]
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1
    else:
        new_numeric_part = 1  

    new_vendor_code = f'V - {new_numeric_part:04d}'

    if request.method == "POST":

        if 'Delete' in request.form:
            vendordata = request.form.getlist('vendordata[]')
            db = get_database()
            cursor = db.cursor()
            try:
                for claim_str in vendordata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM vendors_details WHERE id = ?', (claim_id,))
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            return redirect(url_for('pur_suppliers'))
        
        vendor_code = request.form['vendor_code']
        reg_no = request.form['reg_no']
        company_name = request.form['company_name']
        display_name = request.form['display_name']
        office_no = request.form['office_no']
        website = request.form['website']
        billing_address1 = request.form['billing_address1']
        billing_address2 = request.form['billing_address2']
        city = request.form['city']
        postcode = request.form['postcode']
        country = request.form['country']
        state = request.form['state']
        contact1 = request.form['contact1']
        email1 = request.form['email1']
        mobile1 = request.form['mobile1']
        contact2 = request.form['contact2']
        email2 = request.form['email2']
        mobile2 = request.form['mobile2']
        contact3 = request.form['contact3']
        email3 = request.form['email3']
        mobile3 = request.form['mobile3']
        bank_name = request.form['bank_name']
        tax_id = request.form['tax_id']
        branch_details = request.form['branch_details']
        currency = request.form['currency']
        pay_terms = request.form['pay_terms']
        account_no = request.form['account_no']
        swift = request.form['swift']
        ifsc = request.form['ifsc']
        product_catgory = request.form['Product_Category']
        brand = request.form['Brands']
        Details = request.form['Details']

        try:
            # Check if vendor code exists
            cursor.execute('SELECT id FROM vendors_details WHERE vendor_code = ?', (vendor_code,))
            existing_vendor = cursor.fetchone()

            if existing_vendor:
                # Update existing vendor
                vendor_id = existing_vendor[0]
                cursor.execute( '''UPDATE vendors_details SET reg_no = ?, company_name = ?, display_name = ?, office_no = ?, website = ?, billing_address1 = ?,
                                billing_address2 = ?, city = ?, postcode = ?, country = ?, state = ?, contact1 = ?, email1 = ?, mobile1 = ?, contact2 = ?, email2 = ?,
                                mobile2 = ?, contact3 = ?, email3 = ?, mobile3 = ?, bank_name = ?, tax_id = ?, branch_details = ?, currency = ?, pay_terms = ?, 
                               account_no = ?, swift = ?, ifsc = ?, product_catgory = ?, brand = ?, Details= ?  WHERE id = ?''',
                                [reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, 
                                 contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency,
                                   pay_terms, account_no, swift, ifsc,product_catgory, brand,Details, vendor_id] )
                db.commit()
                flash(f"Vendor details for '{company_name}' have been updated.", 'success')
            
            else:
                # Insert new vendor
                cursor.execute(
                    '''INSERT INTO vendors_details (vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city,
                      postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, 
                      currency, pay_terms, account_no, swift, ifsc, product_catgory, brand,Details) VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    [vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1,
                      email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, 
                      swift, ifsc,product_catgory, brand,Details])
                db.commit()
                flash(f"Vendor details for '{company_name}' have been successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add/update vendor details. Please try again.", 'error')

        return redirect(url_for('prof_supplier'))
    
    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT COUNT(*) FROM vendors_details")
    total_vendors = cursor.fetchone()[0]
    return render_template('admin_templates/profile/prof_supplier.html',user_access=user_access, user=user,vendors=vendors,department_code=department_code,
                          total_vendors=total_vendors, new_vendor_code=new_vendor_code)


###-----------------------------------------------HR---------------------------------------------------------------------------------------------------------

@app.route('/hr')
def hr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM leaves_approved WHERE status = 'Pending'")
    pending_leaves_count = cursor.fetchone()[0]
    department_code = get_department_code_by_username( user['name'])
    db.commit()
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/hr/hr_main_page.html',user_access=user_access,user=user,is_pm=is_pm,department_code=department_code,pending_leaves_count=pending_leaves_count)

from datetime import datetime
from calendar import month_name
from collections import defaultdict
from flask import jsonify, request
from datetime import datetime
import calendar

@app.route('/fetch_employee_leaves_data')
def fetch_employee_leaves_data():
    employeeID = request.args.get('employeeID')
    if not employeeID:
        return jsonify({})  # Return empty dictionary if no employeeID

    db = get_database() 
    cursor = db.cursor()
    insights = {}

# try:
    # Fetch approved leave records from 'leaves' table
    import datetime
    current_year = datetime.datetime.now().year
    cursor.execute(""" SELECT leave_type, leave_date, approved_by, approved_date FROM leaves WHERE employeeID = ?  AND status = 'Approved' AND strftime('%Y', leave_date) = ?
    """, (employeeID, str(current_year)))

    leaves = cursor.fetchall()
    leave_data = defaultdict(list)
    days_used = defaultdict(int)
    monthly_leave_counts = defaultdict(int)
    leave_type_counts = defaultdict(int)
    line_counts = defaultdict(lambda: defaultdict(int))
    from datetime import datetime
    current_year = datetime.now().year
    last_year = current_year - 1
    month_name_full = {
        '01': 'January', '02': 'February', '03': 'March', '04': 'April', '05': 'May', '06': 'June',
        '07': 'July', '08': 'August', '09': 'September', '10': 'October', '11': 'November', '12': 'December'
    }
    month_order = [
        'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 
        'October', 'November', 'December'
    ]
    line_counts = {
        str(current_year): {month: 0 for month in month_order},
        str(last_year): {month: 0 for month in month_order}
    }
    cursor.execute("""
        SELECT strftime('%Y', leave_date) AS year, strftime('%m', leave_date) AS month
        FROM leaves 
        WHERE employeeID = ?  
        AND status = 'Approved'  
        AND strftime('%Y', leave_date) IN (?, ?)
    """, (employeeID, str(current_year), str(last_year)))
    for row in cursor.fetchall():
        year = row[0]  # Year is returned as a string 'YYYY' (e.g., '2024', '2025')
        month = row[1]  # Month is returned as a string 'MM' (e.g., '01', '02', ...)
        month_name = month_name_full.get(month, month)
        if year in line_counts:
            if month_name in line_counts[year]:
                line_counts[year][month_name] += 1
    leaves_count_dict = {year: dict(months) for year, months in line_counts.items()}
    for year in leaves_count_dict:
        sorted_months = {month: leaves_count_dict[year][month] for month in month_order}
        leaves_count_dict[year] = sorted_months

    for leave in leaves:
        leave_type = leave['leave_type'] 
        
        # Format dates
        from datetime import datetime

        leave_date = datetime.strptime(leave['leave_date'], '%Y-%m-%d')
        leave_month = leave_date.strftime('%B')  # Get month name for monthly chart
        leave_date_formatted = leave_date.strftime('%d/%m/%y')
        approved_date = (datetime.strptime(leave['approved_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['approved_date'] else 'N/A')

        leave_entry = { 'leave_date': leave_date_formatted,'approved_by': leave['approved_by'],'approved_date': approved_date}
        leave_data[leave_type].append(leave_entry)
        days_used[leave_type] += 1
        monthly_leave_counts[leave_month] += 1
        leave_type_counts[leave_type] += 1

    all_months = [month for month in calendar.month_name if month]  # List of all month names (excluding empty string)
    monthly_leave_counts = {month: monthly_leave_counts.get(month, 0) for month in all_months}
    cursor.execute("""SELECT Medical, Annual, Maternity, Paternity,Unpaid FROM admin_leave_allocation WHERE EmployeeID = ? AND Year = ?""", (employeeID, datetime.now().year))
    allocation = cursor.fetchone()
    if allocation is None:
        allocation = {"Medical": 0, "Annual": 0, "Maternity": 0, "Paternity": 0, "Unpaid":0}
    else:
        allocation = dict(allocation)  # Convert sqlite3.Row to dict if needed
    cursor.execute("""SELECT Start_Date, Annual, Medical, Maternity, Paternity FROM admin_leave_allocation WHERE EmployeeID = ? AND Year = ?""", (employeeID, datetime.now().year))
    temp = cursor.fetchone()
    if temp is None:
        # Set default values if no record exists
        join_date_str = datetime.now().strftime("%Y-%m-%d")  # Set join date as current date
        # Set all leave entitlements to zero
        annual_leave_entitlement = 0
        medical_leave_entitlement = 0
        maternity_leave_entitlement = 0
        paternity_leave_entitlement = 0
        print("No record found. Setting join date to current date and all leave entitlements to zero.")
    else:
        # Extract values if a record is found
        join_date_str = temp["Start_Date"]
        # Ensure the values are either None or empty string before converting to float
        def safe_float(value):
            if value is None or value == '':
                return 0.0  # Return 0.0 if the value is None or an empty string
            try:
                return float(value)
            except ValueError:
                return 0.0  # Return 0.0 if the conversion fails

        # Extract and convert leave entitlement values
        annual_leave_entitlement = safe_float(temp["Annual"])
        medical_leave_entitlement = safe_float(temp["Medical"])
        maternity_leave_entitlement = safe_float(temp["Maternity"])
        paternity_leave_entitlement = safe_float(temp["Paternity"])

    if join_date_str:
        # Convert join_date_str to a datetime object
        join_date = datetime.strptime(join_date_str, "%Y-%m-%d")
        current_date = datetime.now()
        # print(".join_date.......",join_date)
        # print(".current_date.......",current_date)

        # Calculate the number of days since the employee joined
        days_since_joining = (current_date - join_date).days
        # print("..days_since_joining..........",days_since_joining)
        completed_30_day_periods = days_since_joining // 30  # Number of complete 30-day periods
        # print("..completed_30_day_periods..........",completed_30_day_periods)


        # Function to calculate pro-rated leave
        def calculate_pro_rated_leave(entitlement):
            return completed_30_day_periods * (entitlement / 12)

        # Calculate the pro-rated leave for each leave type
        allocation = {
            "Annual": round(calculate_pro_rated_leave(annual_leave_entitlement), 2),
            "Medical": round(calculate_pro_rated_leave(medical_leave_entitlement), 2),
            "Maternity": round(calculate_pro_rated_leave(maternity_leave_entitlement), 2),
            "Paternity": round(calculate_pro_rated_leave(paternity_leave_entitlement), 2),
            "Unpaid": 0  # Unpaid leave doesn't have a limit, hence setting as -1
        }

        # # Debug information
        print(f"Employee ID: {employeeID}")
        print(f"Days Since Joining: {days_since_joining}")
        print(f"Completed 30-day periods: {completed_30_day_periods}")
        print(f"Pro-rated Annual Leave: {allocation['Annual']} days")
        print(f"Pro-rated Medical Leave: {allocation['Medical']} days")
        print(f"Pro-rated Maternity Leave: {allocation['Maternity']} days")
        print(f"Pro-rated Paternity Leave: {allocation['Paternity']} days")
        print(f"Unpaid Leave: {allocation['Unpaid']}")

    chart_data = { "leave_types": ["Medical", "Annual", "Maternity", "Paternity","Unpaid"],
        "eligible_days": [ allocation["Medical"],allocation["Annual"], allocation["Maternity"],allocation["Paternity"],allocation["Unpaid"]],
        "days_used": [days_used.get("Medical", 0), days_used.get("Annual", 0), days_used.get("Maternity", 0),days_used.get("Paternity", 0),days_used.get("Unpaid", 0)],
        "months": list(monthly_leave_counts.keys()),
        "monthly_leave_counts": list(monthly_leave_counts.values()),
        "leave_counts": list(leave_type_counts.values())}
  
    import datetime
    current_year = datetime.datetime.now().year
    cursor.execute(""" SELECT leave_type, start_date, end_date, number_of_days, status, approved_by, approved_date  FROM leaves_approved  WHERE employeeID = ?   AND strftime('%Y', start_date) = ?   ORDER BY start_date DESC
    """, (employeeID, str(current_year)))
    approved_leaves = cursor.fetchall()
    from datetime import datetime
    # Format approved leaves data with dates in DD/MM/YY format
    approved_leaves_data = []
    for leave in approved_leaves:
        number_of_days = int(''.join(filter(str.isdigit, leave['number_of_days'])))
        approved_leaves_data.append({
            "leave_type": leave['leave_type'],
            "start_date": datetime.strptime(leave['start_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['start_date'] else 'N/A',
            "end_date": datetime.strptime(leave['end_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['end_date'] else 'N/A',
            "number_of_days": number_of_days,
            "status": leave['status'],
            "approved_by": leave['approved_by'],
            "approved_date": datetime.strptime(leave['approved_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['approved_date'] else 'N/A'
        })
    total_used = sum(days_used.values())
    allocation = {key: int(value) if value else 0 for key, value in dict(allocation).items()}
    total_eligible = sum(allocation.values())
    # Insight calculations with error handling
    try:
        # Insight 1: Maximum leaves taken by month
        max_month = max(monthly_leave_counts, key=monthly_leave_counts.get)
        max_leaves_count = monthly_leave_counts[max_month]
        # print(f"Employee has taken maximum leaves in {max_month} with {max_leaves_count} leaves.")
        insights["maximum_leaves_month"] = f"Maximum leaves in {max_month} with {max_leaves_count} leaves."
    except ValueError:
        insights["maximum_leaves_month"] = "Could not determine the month with maximum leaves."

    try:
        # Insight 2: Most common leave type used
        max_leave_type = max(leave_type_counts, key=leave_type_counts.get)
        max_leave_count = leave_type_counts[max_leave_type]
        # print(f"Employee's most common leave type is {max_leave_type} with {max_leave_count} leaves taken.")
        insights["most_common_leave_type"] = f"Most common leave type is {max_leave_type} with {max_leave_count} leaves taken."
    except ValueError:
        insights["most_common_leave_type"] = "Could not determine the most common leave type."

    try:
        # Insight 3: Total leaves used versus eligible leaves
        total_used = sum(days_used.values())
        total_eligible = sum(allocation.values())
        print(f"Employee has used {total_used} out of {total_eligible} eligible leave days this year.")
        insights["total_leaves_usage"] = f"Used {total_used} out of {total_eligible} eligible leave days this year."
    except Exception:
        insights["total_leaves_usage"] = "Error calculating total leaves used."

    try:
        # Insight 4: Leaves not used by type
        unused_leaves = {}
        if isinstance(allocation, (list, tuple)):
            leave_types = ["Medical", "Annual", "Maternity", "Paternity","Unpaid"]
            for i, leave_type in enumerate(leave_types):
                unused_leaves[leave_type] = allocation[i] - days_used.get(leave_type, 0)
        else:
            # If allocation is a dict, access its keys directly
            unused_leaves = {leave_type: allocation[leave_type] - days_used.get(leave_type, 0) for leave_type in allocation}

        unused_summary = ", ".join([f"{leave_type}: {count}" for leave_type, count in unused_leaves.items() if count > 0])
        # print(f"Employee has not used the following leave days: {unused_summary}")
        insights["unused_leaves"] = f"Not used the following leave days: {unused_summary}"
    except Exception as e:
        insights["unused_leaves"] = f"Error fetching unused leave information: {str(e)}"

    try:
        # Insight 7: Last approved leave date
        if leaves:
            last_leave_date = max(datetime.strptime(leave['leave_date'], '%Y-%m-%d') for leave in leaves)
            insights["last_approved_leave_date"] = f"Last approved leave was on {last_leave_date.strftime('%d/%m/%y')}."
        else:
            insights["last_approved_leave_date"] = "No approved leave records found."
        # print(f"Employee's last approved leave was on {last_leave_date.strftime('%d/%m/%y')}.")
    except Exception:
        insights["last_approved_leave_date"] = "Error fetching last approved leave date."

    try:
        # Insight 8: Percentage of leave used
        if total_eligible > 0:
            percentage_used = (total_used / total_eligible) * 100
            insights["percentage_used"] = f"Used {percentage_used:.2f}% of their eligible leave days."
        else:
            insights["percentage_used"] = "No eligible leave days available."
        # print(f"Employee has used {percentage_used:.2f}% of their eligible leave days.")
    except Exception:
        insights["percentage_used"] = "Error calculating percentage of leave used."

# except Exception as e:
#     insights["general_error"] = f"An error occurred while fetching leave data: {str(e)}"
    return jsonify({ "leave_data": leave_data,"chart_data": chart_data,"approved_leaves_data": approved_leaves_data,"insights": insights,
                    "line_chart_data":leaves_count_dict })

@app.route('/get_employee_leave_data', methods=['GET'])
def get_employee_leave_data():
    employee_id = request.args.get('employee_id')
    if not employee_id:
        return jsonify({'error': 'Employee ID is required'}), 400

    db = get_database() 
    cursor = db.cursor()
    # Fetch data for the selected employee
    cursor.execute("SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?", (employee_id,))
    result = cursor.fetchone()

    if result:
        # Convert the result to a dictionary
        data = {
            'exists': True,
            'Annual': result['Annual'],
            'Medical': result['Medical'],
            'Casual': result['Casual'],
            'Maternity': result['Maternity'],
            'Paternity': result['Paternity'],
            'Year': result['Year'],
            'Start_Date': result['Start_Date']
        }
    else:
        data = {'exists': False}
    
    return jsonify(data)

# Function to calculate days since the start date
def calculate_days_since_joined(start_date):
    if not start_date:
        return 0
    start_date = datetime.strptime(start_date, "%Y-%m-%d")
    current_date = datetime.now()
    days_since_joined = (current_date - start_date).days
    return days_since_joined

@app.route('/leave_approvals', methods=['GET', 'POST'])
def leave_approvals(leave_id=None):  
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    table_rows = []
    leave_details = []
    from datetime import datetime
    approved_date = datetime.now().strftime('%Y-%m-%d')
    optionValue = 'leave_dashboard'
    EmployeeID = None
    leave_rows = []
    row_id = None
    approve = False
    leave_approve_form = None

    current_year = datetime.now().year
    cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
    holidays_data = cursor.fetchall()
    public_holidays_count = len(holidays_data)

    if 'add_or_save' in request.form:
        # Get form data
        EmployeeID = request.form['employee_id']
        Medical = request.form['Medical']
        Casual = request.form['Casual']
        Annual = request.form['Annual']
        Maternity = request.form['Maternity']
        Paternity = request.form['Paternity']
        Year = request.form['Year']
        Start_Date = request.form['Start_Date']
        leave_row_id = request.form.get('leave_row_id', None)  # Get the leave_row_id if it exists
        print("..........Start_Date...............", Start_Date)
        
        # Get the current year
        from datetime import datetime
        current_year = datetime.now().year
    
        # Check if there's an existing entry for the same employee and year (if leave_row_id doesn't exist)
        cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ? AND Year = ?', (EmployeeID, Year))
        existing_data = cursor.fetchone()

        # SQL query to count holidays in the current year
        cursor.execute('SELECT COUNT(*) FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
        holiday_count = cursor.fetchone()[0]
        print("Number of public holidays in the current year:", holiday_count)

        if leave_row_id:  # Update the existing entry if leave_row_id is provided
            # Check if the row_id exists
            cursor.execute('SELECT * FROM admin_leave_allocation WHERE id = ?', (leave_row_id,))
            existing_row = cursor.fetchone()

            if existing_row:
                # Update the data for the specific leave_row_id
                update_query = '''UPDATE admin_leave_allocation 
                                SET EmployeeID = ?, Medical = ?, Casual = ?, Annual = ?, Maternity = ?, 
                                    Paternity = ?, Public = ?, Year = ?, Start_Date = ? 
                                WHERE id = ?'''
                db.execute(update_query, (EmployeeID, Medical, Casual, Annual, Maternity, Paternity, holiday_count, Year, Start_Date, leave_row_id))
                db.commit()
                flash(f"Leaves for '{EmployeeID}' updated successfully.", 'update_leaves')
            else:
                flash(f"Error: Leave row with ID '{leave_row_id}' not found.", 'error')
        else:
            if existing_data:
                # Prevent inserting if data for the same employee and year already exists
                flash(f"Error: Leaves for '{EmployeeID}' in year '{Year}' already exist. Cannot add duplicate. Try Editing", 'update_leaves1')
            else:
                # Insert the data as no existing entry is found for the same employee and year
                insert_query = '''INSERT INTO admin_leave_allocation (EmployeeID, Medical, Casual, Annual, Maternity, Paternity, Public, Year, Start_Date) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'''
                db.execute(insert_query, (EmployeeID, Medical, Casual, Annual, Maternity, Paternity, holiday_count, Year, Start_Date))
                db.commit()
                flash(f"Leaves for '{EmployeeID}' added successfully.", 'update_leaves')

        # Fetch updated data to display on the frontend
        cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY EmployeeID COLLATE NOCASE')
        leaves_data = cursor.fetchall()
        user_access = get_employee_access_control(user['name'])
        optionValue = 'leave_allocation'

    if request.method == 'POST':
        leave_id = request.form.get('leave_id') 
        action_type = request.form.get('actionType')
        row_id = request.form.get('row_id') 
        delleaverow = request.form.get('delleaverow')        
        cursor.execute('SELECT * FROM leaves_approved WHERE id = ?', (leave_id,))
        leave_details = cursor.fetchone()

        if row_id:
            cursor = cursor.execute('SELECT * FROM leaves WHERE temp_id =?  ORDER BY id DESC',(row_id,))
            leave_rows = cursor.fetchall()
            db.commit()
            leave_approve_form = 'approve_form'
            optionValue = 'approve_leave'

        if delleaverow:
            cursor.execute('DELETE FROM leaves WHERE id = ?', [delleaverow])
            # Decrease number_of_days by one in leaves_approved where id matches
            delleaverow1 = request.form.get('delleaverow1') 
            cursor.execute('SELECT * FROM leaves_approved WHERE id = ?', [delleaverow1])
            leave_approved = cursor.fetchone()
            if leave_approved:
                current_number_of_days = leave_approved['number_of_days']
                new_number_of_days = int(current_number_of_days.split()[0]) - 1
                updated_number_of_days = f"{new_number_of_days} Days"
                cursor.execute('UPDATE leaves_approved SET number_of_days = ? WHERE id = ?', (updated_number_of_days, delleaverow1))
                db.commit()

            cursor = cursor.execute('SELECT * FROM leaves WHERE temp_id =?  ORDER BY id DESC',(row_id,))
            leave_rows = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved WHERE status = ? ORDER BY id DESC', ('Pending',))
            leaves_yet_to_approve = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()
            db.commit()
            optionValue = 'approve_leave'
            leave_approve_form = 'approve_form'

        db.commit()

    # Get the current year
    current_year = datetime.now().year
    current_month = datetime.now().strftime('%Y-%m')
    current_day = datetime.now().strftime('%Y-%m-%d')
    from datetime import datetime
    # Get the current year
    current_year = datetime.now().year
    dashboard_data = {}
    # 1. Total number of leaves from `leaves` table for the current year
    cursor.execute("SELECT COUNT(*) as total_leaves FROM leaves WHERE strftime('%Y', leave_date) = ?", (str(current_year),))
    dashboard_data['total_leaves'] = cursor.fetchone()['total_leaves']

    # 2. Total number of leaves approved from `leaves_approved` table for the current year
    cursor.execute("SELECT COUNT(*) as total_approved_leaves FROM leaves_approved WHERE status = 'Approved' AND strftime('%Y', approved_date) = ?", (str(current_year),))
    dashboard_data['total_approved_leaves'] = cursor.fetchone()['total_approved_leaves']

    # 3. Total number of leaves rejected from `leaves_approved` table for the current year
    cursor.execute("SELECT COUNT(*) as total_rejected_leaves FROM leaves_approved WHERE status = 'Rejected' AND strftime('%Y', approved_date) = ?", (str(current_year),))
    dashboard_data['total_rejected_leaves'] = cursor.fetchone()['total_rejected_leaves']

    # 4. Total number of pending leaves from `leaves_approved` table for the current year
    cursor.execute("SELECT COUNT(*) as total_Pending_leaves FROM leaves_approved WHERE status = 'Pending' AND strftime('%Y', approved_date) = ?", (str(current_year),))
    dashboard_data['total_Pending_leaves'] = cursor.fetchone()['total_Pending_leaves']

    # 5. Total leaves in the current year
    cursor.execute("SELECT COUNT(*) as total_leaves_current_year FROM leaves WHERE strftime('%Y', leave_date) = ?", (str(current_year),))
    dashboard_data['total_leaves_current_year'] = cursor.fetchone()['total_leaves_current_year']

    # 6. Total leaves in the current month of the current year
    cursor.execute("SELECT COUNT(*) as current_month_leaves FROM leaves WHERE strftime('%Y-%m', leave_date) = ?", (datetime.now().strftime('%Y-%m'),))
    dashboard_data['total_leaves_current_month'] = cursor.fetchone()['current_month_leaves']

    # 7. Total leaves in the current day of the current year
    cursor.execute("SELECT COUNT(*) as current_day_leaves FROM leaves WHERE strftime('%Y-%m-%d', leave_date) = ?", (datetime.now().strftime('%Y-%m-%d'),))
    dashboard_data['total_leaves_current_day'] = cursor.fetchone()['current_day_leaves']

    user_access = get_employee_access_control(user['name'])

    department_code = get_department_code_by_username(user['name'])
    cursor = cursor.execute('SELECT * FROM leaves_approved WHERE status = ? ORDER BY id DESC', ('Pending',))
    leaves_yet_to_approve = cursor.fetchall()
    cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
    approved_leaves = cursor.fetchall()


    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY Year DESC, EmployeeID COLLATE NOCASE')
    leaves_data = cursor.fetchall()


    # print("..........optionValue.........",optionValue)
    return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves,EmployeeID=EmployeeID, 
                           leave_rows=leave_rows,row_id=row_id,optionValue=optionValue,user_access=user_access,department_code=department_code,
                           leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows,dashboard_data=dashboard_data,
                           approve=approve,usernames=usernames,leaves_data=leaves_data,holidays_data=holidays_data,leave_approve_form = leave_approve_form)

@app.route('/get_leave_detils_for_approve')
def get_leave_detils_for_approve():
    leave_id = request.args.get('rowNumber')
    db = get_database()
    cursor = db.cursor()
    from datetime import datetime

    # leave_id = request.form.get('leave_id') 
    
    cursor.execute('SELECT * FROM leaves_approved WHERE id = ?', (leave_id,))
    leave_details = cursor.fetchone()

    if leave_details:
        EmployeeID = leave_details['employeeID']
        current_leave_type = leave_details['leave_type']  # Get leave type from leave_details
        lev_startdate = leave_details['start_date']
        lev_enddate = leave_details['end_date']
        requested_days = (datetime.strptime(lev_enddate, '%Y-%m-%d') - datetime.strptime(lev_startdate, '%Y-%m-%d')).days 

        leave_types = ['Medical', 'Unpaid', 'Annual', 'Maternity', 'Paternity']
        eligibility_dict = {leave_type: 0 for leave_type in leave_types}
        
        def safe_float(value):
            if value is None or value == '':
                return 0.0  
            try:
                return float(value)
            except ValueError:
                return 0.0  
        cursor.execute('SELECT Start_Date, Annual, Medical, Maternity, Paternity FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
        employee_leave_eligibility_data = cursor.fetchone()


        if employee_leave_eligibility_data:
            join_date_str = employee_leave_eligibility_data['Start_Date']
            annual_leave_entitlement = safe_float(employee_leave_eligibility_data['Annual'])
            medical_leave_entitlement = safe_float(employee_leave_eligibility_data['Medical'])
            maternity_leave_entitlement = safe_float(employee_leave_eligibility_data['Maternity'])
            paternity_leave_entitlement = safe_float(employee_leave_eligibility_data['Paternity'])
            join_date = datetime.strptime(join_date_str, "%Y-%m-%d")
            current_date = datetime.now()
            days_since_joining = (current_date - join_date).days
            completed_30_day_periods = days_since_joining // 30  # Full 30-day periods
            def calculate_pro_rated_leave(entitlement):
                return completed_30_day_periods * (entitlement / 12)

            eligibility_dict = {
                "Annual": round(calculate_pro_rated_leave(annual_leave_entitlement), 2),
                "Medical": round(calculate_pro_rated_leave(medical_leave_entitlement), 2),
                "Maternity": round(calculate_pro_rated_leave(maternity_leave_entitlement), 2),
                "Paternity": round(calculate_pro_rated_leave(paternity_leave_entitlement), 2),
                "Unpaid": -1  
            }

        else:
            print(f"No leave data found for EmployeeID: {EmployeeID}.")

        cursor.execute('''SELECT leave_type, COUNT(*) AS total_days_used FROM leaves WHERE employeeID = ? GROUP BY leave_type''', (EmployeeID,))
        employee_leave_used_data = cursor.fetchall()

        used_dict = {row['leave_type']: row['total_days_used'] for row in employee_leave_used_data}
        if 'Medical' in used_dict:
            used_dict['Medical'] = used_dict.pop('Medical')

        table_rows = []
        for leave_type in eligibility_dict:
            eligibility = eligibility_dict.get(leave_type, 0)
            used = used_dict.get(leave_type, 0)
            left = eligibility - used
            table_rows.append((leave_type, eligibility, used, left))

        print("...........table_rows.............",table_rows)
        print("...........leave_details.............",leave_details)
        return jsonify({
                'success': True,
                'table_rows': table_rows,
                'leave_details': dict(leave_details) if leave_details else None
            })

@app.route('/approve_or_reject_leave', methods=['POST'])
def approve_or_reject_leave():
    action_type = request.form.get('action_type')

    db = get_database()
    cursor = db.cursor()
    current_user = get_current_user()
    from datetime import datetime, timedelta
    from dateutil import parser

    if action_type == 'Approve':

        id1 = request.form.get('modalleave_id')

        if id1:
            current_user = get_current_user()
            db = get_database()
            cursor = db.cursor()
            public_holidays = set()
            cursor.execute('SELECT date FROM public_holidays')
            public_holidays_data = cursor.fetchall()
            for holiday in public_holidays_data:
                public_holidays.add(parser.parse(holiday['date']).date())

            approved_date = datetime.now().date()
            # Update leave status
            cursor.execute('UPDATE leaves_approved SET status = ?, approved_by = ?, approved_date = ? WHERE id = ?',('Approved', current_user['name'], approved_date, id1))
            cursor.execute('SELECT * FROM leaves_approved WHERE id=?', (id1,))
            leave_details = cursor.fetchone()
            department_code = leave_details['department_code']
            # Process number_of_days format
            number_of_days = leave_details['number_of_days']
            if 'Days' in number_of_days:
                number_of_days = 'L'
            elif 'Half Day' in number_of_days:
                number_of_days = number_of_days.replace('Half Day', 'HF')
            elif 'Hours' in number_of_days:
                number_of_days = number_of_days.replace('Hours', 'Hr')

            # Insert each day into the leaves table
            start_date1 = parser.parse(leave_details['start_date']).date()
            end_date1 = parser.parse(leave_details['end_date']).date()

            current_date = start_date1

            while current_date <= end_date1:
                if current_date.weekday() not in (5, 6) and current_date not in public_holidays:
                    cursor.execute('''INSERT INTO leaves (employeeID, section_code, leave_type, leave_date, leave_duration, department_code, status, 
                                    approved_by, approved_date,temp_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)''',
                        (leave_details['employeeID'], leave_details['section_code'], leave_details['leave_type'], current_date.strftime('%Y-%m-%d'),
                            number_of_days, department_code, 'Approved', current_user['name'], approved_date,id1))
                current_date += timedelta(days=1)


            current_user = current_user['name']
            user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', [leave_details['employeeID']])
            mail_to_row = user_cur.fetchone()

            # Ensure that an email was found for the user
            if mail_to_row:
                mail_to = mail_to_row['name']
                print(".......mail_to............", mail_to)

                # Sending the leave notification email
                # send_leaves_notification(mail_to, leave_details)
            else:
                print(f"No email found for user: {leave_details['employeeID']}")

            db.commit()

        else:

            return jsonify({'success': False, 'message': 'Leave ID not found.'})

        return jsonify({'success': True, 'message': 'Leave approved.'})

    elif action_type == 'Reject':

        id1 = request.form.get('modalleave_id')

        if id1:
            current_user = get_current_user()
            db = get_database()
            cursor = db.cursor()
            cursor.execute('UPDATE leaves_approved SET status=? WHERE id=?',('Rejected', id1))
            cursor.execute('SELECT * FROM leaves_approved WHERE id=?', (id1,))
            leave_details = cursor.fetchone()
            
            user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', [leave_details['employeeID']])
            mail_to_row = user_cur.fetchone()

            # Ensure that an email was found for the user
            if mail_to_row:
                mail_to = mail_to_row['name']
                print(".......mail_to............", mail_to)
                # Sending the leave notification email
                # send_leaves_notification(mail_to, leave_details)
            else:
                print(f"No email found for user: {leave_details['employeeID']}")
            db.commit()
        
        return jsonify({'success': True, 'message': 'Leave Rejected.'})

    return jsonify({'success': False, 'message': 'Invalid action type.'})

import calendar
from flask import jsonify

@app.route('/get_leave_data')
def get_leave_data():
    # Connect to SQLite database
    db = get_database()
    conn = db

    # Query to get the most leave employee data and group by year
    most_leave_employee_df = pd.read_sql_query("""
        SELECT employeeID, leave_count, year
        FROM (
            SELECT employeeID, COUNT(*) AS leave_count, strftime('%Y', approved_date) AS year,
                ROW_NUMBER() OVER (PARTITION BY strftime('%Y', approved_date) ORDER BY COUNT(*) DESC) AS row_num
            FROM leaves
            GROUP BY employeeID, year
        )
        WHERE row_num <= 2
        ORDER BY year DESC, leave_count DESC
    """, conn)

    # Query to get average leave duration grouped by year
    avg_leave_duration_df = pd.read_sql_query("""
        SELECT AVG(number_of_days) AS avg_duration, strftime('%Y', approved_date) AS year 
        FROM leaves_approved
        GROUP BY year
    """, conn)

    # Query to get leave data by department and group by year
    leave_by_dept_df = pd.read_sql_query("""
        SELECT a.department_code, 
               COUNT(*) AS leave_count, 
               SUM(CASE WHEN l.status = 'Approved' THEN 1 ELSE 0 END) AS approved_count,
               strftime('%Y', l.approved_date) AS year
        FROM leaves_approved l
        JOIN admin_user a ON l.employeeID = a.username
        GROUP BY a.department_code, year
    """, conn)

    # Query to get frequent leave days and group by year
    frequent_leave_days_df = pd.read_sql_query("""
        SELECT strftime('%w', approved_date) AS weekday, COUNT(*) AS count, strftime('%Y', approved_date) AS year
        FROM leaves_approved 
        GROUP BY weekday, year
    """, conn)

    # Query to get year-wise and month-wise leave count
    leave_counts_df = pd.read_sql_query("""
        SELECT strftime('%Y', leave_date) as year, 
               strftime('%m', leave_date) as month_number,
               COUNT(*) as count 
        FROM leaves 
        GROUP BY year, month_number 
        ORDER BY year, month_number;
    """, conn)

    # Group year-wise leave counts
    yearly_leave_counts = {}
    month_names = [calendar.month_name[i] for i in range(1, 13)]
    for _, row in leave_counts_df.iterrows():
        year, month_number, count = row['year'], row['month_number'], row['count']
        month_name = calendar.month_name[int(month_number)]
        yearly_leave_counts.setdefault(year, {}).update({month_name: count})

    for year in yearly_leave_counts:
        yearly_leave_counts[year] = {month: yearly_leave_counts[year].get(month, 0) for month in month_names}

    # Fetch total number of leaves for each leave type, grouped by year
    all_leave_types = ["Medical", "Annual", "Maternity", "Paternity", "Unpaid"]
    leave_type_counts_df = pd.read_sql_query("""
        SELECT strftime('%Y', leave_date) as year, leave_type, COUNT(*) as count 
        FROM leaves 
        GROUP BY year, leave_type
        ORDER BY year, leave_type;
    """, conn)

    leave_type_counts_by_year = {}
    for _, row in leave_type_counts_df.iterrows():
        year, leave_type, count = row['year'], row['leave_type'], row['count']
        leave_type_counts_by_year.setdefault(year, {}).update({leave_type: count})

    leave_type_counts = {year: {lt: leave_type_counts_by_year.get(year, {}).get(lt, 0) for lt in all_leave_types} for year in yearly_leave_counts}

    # Group other data by year
    most_leave_employee = most_leave_employee_df.groupby('year').apply(lambda x: x[['employeeID', 'leave_count']].to_dict(orient='records')).to_dict()
    avg_leave_duration = avg_leave_duration_df.groupby('year').apply(lambda x: x[['avg_duration']].to_dict(orient='records')).to_dict()
    leave_by_department = leave_by_dept_df.groupby('year').apply(lambda x: x[['department_code', 'leave_count', 'approved_count']].to_dict(orient='records')).to_dict()
    frequent_leave_days = frequent_leave_days_df.groupby('year').apply(lambda x: x[['weekday', 'count']].to_dict(orient='records')).to_dict()

    db = get_database()
    cursor = db.cursor()  # ✅ Get the cursor

    # Execute the query
    query = """
    SELECT 
        a.Year,
        c.code || ' - ' || c.expenses_name AS department,
        SUM(
            COALESCE(a.Medical, 0) + 
            COALESCE(a.Casual, 0) + 
            COALESCE(a.Annual, 0) + 
            COALESCE(a.Maternity, 0) + 
            COALESCE(a.Paternity, 0) + 
            COALESCE(a.Public, 0) + 
            COALESCE(a.Unpaid, 0)
        ) AS total_allocated_leaves
    FROM admin_leave_allocation a
    JOIN admin_user u ON a.EmployeeID = u.username
    JOIN cost_center c ON u.department_code = c.code
    GROUP BY a.Year, department
    ORDER BY a.Year DESC;

    """

    cursor.execute(query)
    rows = cursor.fetchall()

    # Format results into the expected dictionary format
    department_leave_allocation = defaultdict(dict)
    for year, department, total_leaves in rows:
        department_leave_allocation[year][department] = total_leaves

    # print(dict(department_leave_allocation))

    # Combine the grouped data into the dashboard data structure
    dashboard_data = {
        'yearly_leave_counts': yearly_leave_counts,
        'leave_type_counts': leave_type_counts,
        'most_leave_employee': most_leave_employee,
        'avg_leave_duration': avg_leave_duration,
        'leave_by_department': leave_by_department,
        'frequent_leave_days': frequent_leave_days,
        'department_leave_allocation':dict(department_leave_allocation)
    }

    # print(".......dashboard_data.........\n", dashboard_data)

    return jsonify(dashboard_data)

@app.route('/delete_leave/<int:id>', methods=['DELETE'])
def delete_leave(id):
    try:
        db = get_database()
        cursor = db.cursor()

        # Delete from leaves_approved table
        cursor.execute('DELETE FROM leaves_approved WHERE id = ?', [id])

        # Delete from leaves table (based on temp_id)
        cursor.execute('DELETE FROM leaves WHERE temp_id = ?', [id])

        db.commit()
        return jsonify({'success': True, 'message': 'Leave deleted successfully.'})

    except Exception as e:
        db.rollback()
        print(f"Error deleting leave: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete leave.'})

@app.route('/delete_employee_leave_data/<int:id>', methods=['GET'])
@login_required
def delete_employee_leave_data(id):
    db = get_database()
    cursor = db.cursor()
    # Delete the row with the specified id
    cursor.execute('DELETE FROM admin_leave_allocation WHERE id = ?', (id,))
    db.commit()
    # Redirect to the page that displays the table
    return redirect(url_for('leave_approvals'))

def send_leaves_notification(receiver_email, leave_details):
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")
    subject = "Leave Request Status Notification"
    body = (f"Dear {leave_details['employeeID']},\n\n"
            f"I am writing to inform you about the status of your leave request for {leave_details['number_of_days']}. "
            f"Your leave has been {leave_details['status']}.\n\n"
            f"Details of your leave request are as follows:\n"
            f"- Start Date: {leave_details['start_date']}\n"
            f"- End Date: {leave_details['end_date']}\n\n"
            "If you have any questions or need further assistance, please do not hesitate to contact me.\n\n"
            "Best regards,\n"
            "Centroid Engineering Solutions")
    
    message = MIMEMultipart()
    message['From'] = "cestimesheet67@gmail.com"
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    
    s.sendmail("cestimesheet67@gmail.com", receiver_email, message.as_string())
    print('Leave notification email sent successfully.')
    s.quit()

@app.route('/hr_add',methods=['GET', 'POST'])
@login_required
def hr_add():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])


    EmployeeID = user['name']
    leave_types = ['Medical', 'Casual', 'Annual', 'Maternity', 'Paternity']
    eligibility_dict = {leave_type: 0 for leave_type in leave_types}
    cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
    employee_leave_eligibility_data = cursor.fetchall()

    for row in employee_leave_eligibility_data:
        row_dict = dict(row)

        for leave_type in leave_types:
            leave_value = row_dict.get(leave_type, 0) 

            if isinstance(leave_value, (int, float)):
                eligibility_dict[leave_type] += int(leave_value)
            elif isinstance(leave_value, str) and leave_value.strip():
                try:
                    eligibility_dict[leave_type] += int(leave_value)
                except ValueError:
                    print(f"Invalid value for {leave_type}: {leave_value}")
            else:
                print(f"Empty or non-string value for {leave_type}")

    cursor.execute('''SELECT leave_type, COUNT(*) AS total_days_used FROM leaves WHERE employeeID = ? GROUP BY leave_type''', (EmployeeID,))
    employee_leave_used_data = cursor.fetchall()

    used_dict = {row['leave_type']: row['total_days_used'] for row in employee_leave_used_data}
    if 'Medical' in used_dict:
        used_dict['Medical'] = used_dict.pop('Medical')
    table_rows = []
    # Iterate through leave types and populate the table
    for leave_type in eligibility_dict:
        eligibility = eligibility_dict.get(leave_type, 0)
        used = used_dict.get(leave_type, 0)
        left = eligibility - used
        # Append a tuple representing a table row
        table_rows.append((leave_type, eligibility, used, left))
    table_rows = [(leave_type.replace('Medical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]

    cursor.execute('SELECT * FROM leaves WHERE EmployeeID = ?', (EmployeeID,))
    leaves = cursor.fetchall()
    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted( [row[0] for row in cursor.fetchall()] )
    cursor = db.execute('SELECT * FROM courses ORDER BY id DESC')
    courses = cursor.fetchall()
    cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
    assets = cursor.fetchall()
    option = None

    if request.method == 'POST':

        form_type = request.form.get('form_type')
        Delete = request.form.get('Delete_Course')
        Delete_Asset = request.form.get('Asset_Delete')
        Delete_Leave = request.form.get('Delete_Leave')
        holiday_Delete = request.form.get('holiday_Delete')

        if Delete:
            db.execute("DELETE FROM courses WHERE id = ?", (Delete,))
            db.commit()
            option = 'courses'
            flash(f" Course deleted successfully.", 'course_flash_sus')

        if Delete_Asset:
            db.execute("DELETE FROM assets WHERE id = ?", (Delete_Asset,))
            db.commit()
            option = 'asset'
            flash(f"Asset row deleted Successfully.", 'asset_sus')

        if Delete_Leave:
            db.execute("DELETE FROM admin_leave_allocation WHERE id = ?", (Delete_Leave,))
            db.commit()
            option = 'leave'
            flash(f"Leave row deleted Successfully.", 'leaves_sus')
        
        if holiday_Delete:
            db.execute("DELETE FROM public_holidays WHERE id = ?", (holiday_Delete,))
            db.commit()
            option = 'holiday'
            flash(f"Holiday deleted Successfully.", 'holiday_add')


        if form_type == 'course':
            Course_Name = request.form['Course_Name']
            existing_course = db.execute("SELECT * FROM courses WHERE Course_Name = ?", (Course_Name,)).fetchone()
            if existing_course:
                flash(f"Course '{Course_Name}' already exists.", 'course_flash_err')
            else:
                db.execute("INSERT INTO courses (Course_Name) VALUES (?)", (Course_Name,))
                db.commit()
                flash(f"Course added successfully.", 'course_flash_sus')
            option = 'courses'

        elif form_type == 'asset':
            Asset_Name = request.form['Asset_Name']
            Model = request.form['Model']
            S_N = request.form['S_N']
            cursor.execute('SELECT * FROM assets WHERE S_N = ?', (S_N,))
            existing_data = cursor.fetchone()
            if existing_data:
                flash(f" Asset with '{S_N}' already exists.", 'asset_err')
            else:
                db.execute("INSERT INTO assets (Asset_Name, Model, S_N, status) VALUES (?, ?, ?, ?)", (Asset_Name, Model, S_N, 'Open'))
                db.commit()
                flash(f" Asset Added successfully.", 'asset_sus')
            option = 'asset'
            
        elif form_type == 'leave':
            EmployeeID = request.form['employee_id']
            Medical = request.form['Medical']
            # Casual = request.form['Casual']
            Annual = request.form['Annual']
            Maternity = request.form['Maternity']
            Paternity = request.form['Paternity']
            # Check if EmployeeID already exists
            cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
            existing_data = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) FROM public_holidays')
            holiday_count = cursor.fetchone()[0]

            if existing_data:
                # EmployeeID exists, update the values
                update_query = ''' UPDATE admin_leave_allocation SET Medical = ?, Annual = ?, Maternity = ?, Paternity = ?, Public=? WHERE EmployeeID = ?'''
                db.execute(update_query, (Medical, Annual, Maternity, Paternity,holiday_count, EmployeeID))
                cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
                flash(f"Leaves for '{EmployeeID}' Successfully Updated.", 'leaves_sus')
            else:
                # EmployeeID does not exist, insert a new row
                insert_query = '''INSERT INTO admin_leave_allocation (EmployeeID, Medical, Annual, Maternity, Paternity, Public) VALUES ( ?, ?, ?, ?, ?, ?)'''
                db.execute(insert_query, (EmployeeID, Medical, Annual, Maternity, Paternity, holiday_count))
                cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
                flash(f"Leaves for '{EmployeeID}' Successfully Added.", 'leaves_sus')
            db.commit()
            option = 'leave'

        elif form_type == 'add_holiday':
            holiday_date = request.form['holiday_date']
            holiday_description = request.form['holiday_description']

            check_query = 'SELECT COUNT(*) FROM public_holidays WHERE date = ?'
            cursor.execute(check_query, (holiday_date,))
            result = cursor.fetchone()
            
            if result[0] > 0:
                flash('The date already exists in the List!', 'date_exists')
            else:
                insert_query = '''INSERT INTO public_holidays (date, discription) VALUES (?,?)'''
                cursor.execute(insert_query, (holiday_date,holiday_description))

                flash('Holiday added successfully!', 'holiday_add')
                db.commit()
            option = 'holiday'


    cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY id DESC')
    leaves_data = cursor.fetchall()
    cursor = db.execute('SELECT * FROM courses ORDER BY id DESC')
    courses = cursor.fetchall()
    cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
    assets = cursor.fetchall()
    from datetime import datetime
    current_year = datetime.now().year
    cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
    holidays_data = cursor.fetchall()
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/hr/hr_add.html',is_pm=is_pm,department_code=department_code, user=user, table_rows=table_rows, leaves=leaves, 
                           assets=assets,holidays_data=holidays_data,
                          user_access=user_access,leaves_data=leaves_data, option=option, courses=courses, usernames=usernames)

@app.route('/hr_employee_bio', methods=['GET', 'POST'])
def hr_employee_bio():

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    # Fetch usernames and department codes from admin_user table
    Q1 = """SELECT username, department_code FROM admin_user"""
    user_data1 = db.execute(Q1).fetchall()

    # Convert rows to dictionaries and sort by username
    user_data = [dict(row) for row in user_data1]
    user_data = sorted(user_data, key=lambda x: x['username'].lower())

    # Execute the PRAGMA table_info command to get the columns of the employee_details table
    cursor = db.execute("PRAGMA table_info(employee_details)")
    columns_info = cursor.fetchall()

    # List of all fields in the employee_details table
    fields = [column['name'] for column in columns_info]

    # Total number of fields
    total_fields = len(fields)

    # Function to calculate percentage of profile data loaded
    def calculate_profile_completion(employee):
        non_empty_fields = sum(1 for field in fields if employee[field] not in (None, ''))
        return (non_empty_fields / total_fields) * 100

    # Fetch employee details and calculate profile completion
    for user1 in user_data:
        username = user1['username']
        Q2 = """SELECT * FROM employee_details WHERE display_Name = ?"""
        employee = db.execute(Q2, (username,)).fetchone()
        
        if employee:
            employee_dict = dict(employee)
            profile_completion = calculate_profile_completion(employee_dict)
            # Round the profile_completion to no decimal places
            user1['profile_completion'] = round(profile_completion)
        else:
            user1['profile_completion'] = 0  # No profile data available

    option =  'bio'
    courses_dict = {}
    asset_dict= {}
    Semp =  None
    Semp_code = None
    content = 1
    emp_data = {}
    employee_id = request.args.get('employee_id')

    if employee_id:

        content = 2
        Semp = employee_id
        Semp_code = get_department_code_by_username(Semp)
        # Query to fetch all courses and their attendance details for the given employee
        query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
        cursor = db.execute(query, (employee_id,))
        courses = cursor.fetchall()

        # Create the courses_dict directly from the query result
        courses_dict = {
            course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
            for course_id, course_name, date_attained, expiry_date in courses
            if date_attained is not None or expiry_date is not None}
        
        # Convert the dictionary to a list of dictionaries as required
        courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

        # Fetch all assets
        cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
        all_assets = cursor.fetchall()
        cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
        issued_assets = cursor.fetchall()
        # Create a dictionary with issued assets that have Date_Issued or Date_Returned
        for issued_asset in issued_assets:
            asset_type, date_issued, model, serial_number, date_returned = issued_asset
            if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                for course in all_assets:
                    asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                    if Asset_Name == asset_type and model == Model and serial_number == S_N:
                        asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

        cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                    Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                    Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                    Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Pass_Exp_Date, Emergency_Contact_No
                            FROM employee_details 
                            WHERE display_Name = ?''', (employee_id,))

        emp_data = cursor.fetchone()

    if 'action' in request.form:
        action = request.form['action']
        # print("action...................",action)

        if action == 'Add_or_Update_bio':

            employee_id = request.form.get('employee_id7')
            # print("Employee ID...................", employee_id)

            # Extract data from the form
            display_Name = request.form.get('display_Name')
            Semp_code = get_department_code_by_username(display_Name)
            Full_Employee_ID = request.form.get('Full_Employee_ID')
            designation = request.form.get('Designation')
            Expense_Code = request.form.get('Expense_Code')
            email_id = request.form.get('Email_Id')
            race = request.form.get('Race')
            sector = request.form.get('Sector')
            date_joined = request.form.get('Date_Joined')
            date_left = request.form.get('Date_Left')
            employee_status = request.form.get('Employee_Status')
            username_portal = request.form.get('Username_Portal')
            password_portal = request.form.get('Password_Portal')
            nationality = request.form.get('Nationality')
            pass_type = request.form.get('Pass_Type')
            nric = request.form.get('NRIC')
            fin = request.form.get('FIN')
            wp = request.form.get('WP_NO')
            # print(".............wp................",wp)
            passport_no = request.form.get('Passport_No')
            passport_exp_date = request.form.get('Passport_Exp_Date')
            dob = request.form.get('DOB')
            phone_no = request.form.get('Phone_No')
            personal_mail = request.form.get('Personal_Mail')
            address = request.form.get('Address')
            emergency_contact = request.form.get('Emergency_Contact')
            emergency_contact_address = request.form.get('Emergency_Contact_Address')
            relation_to_employee = request.form.get('Relation_to_Employee')
            basic = request.form.get('Basic')
            employee_cpf = request.form.get('Employee_cpf')
            employer_cpf = request.form.get('Employer_cpf')
            allowance_housing = request.form.get('Allowance_Housing')
            allowance_transport = request.form.get('Allowance_Transport')
            allowance_phone = request.form.get('Allowance_Phone')
            allowance_others = request.form.get('Allowance_Others')
            fund_cdac = request.form.get('Fund_CDAC')
            fund_ecf = request.form.get('Fund_ECF')
            fund_mbmf = request.form.get('Fund_MBMF')
            fund_sinda = request.form.get('Fund_SINDA')
            deduction_housing = request.form.get('Deduction_Housing')
            deduction_transport = request.form.get('Deduction_Transport')
            deduction_phone = request.form.get('Deduction_Phone')
            deduction_others = request.form.get('Deduction_Others')
            levy = request.form.get('Levy')
            sdl = request.form.get('SDL')
            total = request.form.get('Total')
            rate_hr = request.form.get('Rate_per_hr')
            rate_day = request.form.get('Rate_per_day')
            annual_leave = request.form.get('Annual_Leave')
            Pass_Exp_Date = request.form.get('Pass_Exp_Date')
            Date_of_Application = request.form.get('Date_of_Application')
            Emergency_Contact_No = request.form.get('Emergency_Contact_No')

            cursor.execute("SELECT COUNT(*) FROM employee_details WHERE display_Name = ?", (display_Name,))
            count = cursor.fetchone()[0]

            if count > 0:
                # Update existing record
                cursor.execute("""
                    UPDATE employee_details SET
                        Full_Employee_ID = ?, Designation = ?, Expense_Code = ?, Email_Id = ?,Race = ?, Sector = ?, Date_Joined = ?, Date_Left = ?, Employee_Status = ?,
                        UserName_Portal = ?, Password_Portal = ?, Nationality = ?, Pass_Type = ?, NRIC = ?, FIN = ?, WP = ?, Passport_No = ?,
                        Passport_Exp_Date = ?, DOB = ?, Phone_No = ?, Personal_Mail = ?, Address = ?, Emergency_Contact = ?, Emergency_Contact_Address = ?,
                        Relation_to_Employee = ?, Basic = ?, Levy = ?, SDL = ?, Employee_cpf = ?, Employer_cpf = ?, Allowance_Housing = ?, Allowance_Transport = ?,
                        Allowance_Phone = ?, Allowance_Others = ?, Fund_CDAC = ?, Fund_ECF = ?, Fund_MBMF = ?, Fund_SINDA = ?, Deduction_Housing = ?,
                        Deduction_Transport = ?, Deduction_Phone = ?, Deduction_Others = ?, Total = ?, Rate_hr = ?, Rate_day = ?, Annual_Leave = ?, Pass_Exp_Date=?, Date_of_Application=?, Emergency_Contact_No=?
                       WHERE display_Name = ?
                """, (
                    Full_Employee_ID, designation, Expense_Code, email_id, race, sector, date_joined, date_left, employee_status,
                    username_portal, password_portal, nationality, pass_type, nric, fin, wp, passport_no,
                    passport_exp_date, dob, phone_no, personal_mail, address, emergency_contact, emergency_contact_address,
                    relation_to_employee,basic, levy, sdl, employee_cpf, employer_cpf, allowance_housing, allowance_transport, allowance_phone,allowance_others,fund_cdac,fund_ecf,fund_mbmf,fund_sinda,
                    deduction_housing, deduction_transport, deduction_phone, deduction_others , total, rate_hr, rate_day, annual_leave,Pass_Exp_Date, Date_of_Application,Emergency_Contact_No, display_Name
                ))
                flash('Employee details updated successfully!', 'hr_employee_bio_profile_success')

            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO employee_details (
                        Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector,
                        Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal,
                        Nationality, Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date,
                        DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address,
                        Relation_to_Employee, Basic, Employee_cpf, Employer_cpf, Allowance_Housing,
                        Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF,
                        Fund_MBMF, Fund_SINDA, Deduction_Housing, Deduction_Transport, Deduction_Phone,
                        Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    Full_Employee_ID, display_Name, designation, Expense_Code, email_id, race, sector,
                    date_joined, date_left, employee_status, username_portal, password_portal,
                    nationality, pass_type, nric, fin, wp, passport_no, passport_exp_date,
                    dob, phone_no, personal_mail, address, emergency_contact, emergency_contact_address,
                    relation_to_employee, basic, employee_cpf, employer_cpf, allowance_housing,
                    allowance_transport, allowance_phone, allowance_others, fund_cdac, fund_ecf,
                    fund_mbmf, fund_sinda, deduction_housing, deduction_transport, deduction_phone,
                    deduction_others, levy, sdl, total, rate_hr, rate_day, annual_leave,Pass_Exp_Date, Date_of_Application,Emergency_Contact_No
                ))
                flash('Employee details added successfully!', 'hr_employee_bio_profile_success')
            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()
            # print("......employee_id.......",employee_id)

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None }
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (display_Name,))
            emp_data = cursor.fetchone()


            db.commit()

            option = 'bio'
            Semp = display_Name
            content = 2

        if action == 'updateCourse':
            employee_id = request.form.get('employee_id7')
            selected_courses = request.form.getlist('selected_courses[]')
            Semp_code = get_department_code_by_username(employee_id)

            for course_id in selected_courses:
                course_name = request.form.get(f'course_name_{course_id}')
                date_attained = request.form.get(f'date_attained_{course_id}')
                expiry_date = request.form.get(f'expiry_date_{course_id}')
                if date_attained and expiry_date:
                    # Check if the record already exists
                    cursor.execute(""" SELECT * FROM attended_courses WHERE Employee_ID = ? AND Course_Name = ?  """, (employee_id, course_name))
                    existing_row = cursor.fetchone()
                    if existing_row:
                        # Update the existing record
                        cursor.execute(""" UPDATE attended_courses SET Date_Attained = ?, Expiry_Date = ? WHERE Employee_ID = ? AND Course_Name = ? """, (date_attained, expiry_date, employee_id, course_name))
                    else:
                        # Insert a new record
                        cursor.execute(""" INSERT INTO attended_courses (Employee_ID, Course_Name, Date_Attained, Expiry_Date) VALUES (?, ?, ?, ?) """, (employee_id, course_name, date_attained, expiry_date))
            
            flash('Course Updated successfully!', 'employee_course_update_success')

            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None  }
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (employee_id,))
            emp_data = cursor.fetchone()

            option = 'update_course'
            Semp = employee_id
            content = 2

        if action == 'updateAsset':
            employee_id = request.form.get('employee_id77')
            selected_assets = request.form.getlist('selected_assets[]')
            Semp_code = get_department_code_by_username(employee_id)

            # Iterate through selected assets to update or insert records
            for asset_id in selected_assets:
                asset_name = request.form.get(f'asset_name_{asset_id}')
                date_issued = request.form.get(f'date_attained_{asset_id}')
                date_returned = request.form.get(f'expiry_date_{asset_id}')
                model = request.form.get(f'model_{asset_id}')
                serial_number = request.form.get(f'serial_number_{asset_id}')

                if date_issued or date_returned:
                    # Check if the record already exists
                    cursor.execute("""SELECT * FROM issued_assets WHERE Employee_ID = ? AND Asset_Type = ?""", (employee_id, asset_name))
                    existing_row = cursor.fetchone()

                    if existing_row:
                        # Update the existing record
                        cursor.execute("""UPDATE issued_assets SET Date_Issued = ?, Date_Returned = ?, Model = ?, Serial_Number = ? WHERE Employee_ID = ? AND Asset_Type = ?""",
                                    (date_issued, date_returned, model, serial_number, employee_id, asset_name))
                    else:
                        # Insert a new record
                        cursor.execute("""INSERT INTO issued_assets (Employee_ID, Asset_Type, Model, Serial_Number, Date_Issued, Date_Returned) VALUES (?, ?, ?, ?, ?, ?)""",
                                    (employee_id, asset_name, model, serial_number, date_issued, date_returned))
            flash('Asset Updated successfully!', 'employee_asset_update_success')
             
            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None }
            
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (employee_id,))
            emp_data = cursor.fetchone()
            option = 'update_asset'
            Semp = employee_id
            content = 2
        
        if action == 'addCourse':
            employee_id = request.form.get('employee_id17')
            course_name = request.form.get('selected_course')
            date_attained = request.form.get('Date_Attained')
            expiry_date = request.form.get('Expiry_Date')
            Semp_code = get_department_code_by_username(employee_id)
            

            if employee_id and course_name and date_attained:
                # Check if the employee has already attained the course
                cursor.execute("SELECT * FROM attended_courses WHERE Employee_ID = ? AND Course_Name = ?", (employee_id, course_name))
                existing_course = cursor.fetchone()

                if existing_course:
                    flash('Employee has already attained this course.', 'hr_employee_add_course_error1')
                else:
                    # Insert the new course data
                    cursor.execute("INSERT INTO attended_courses (Employee_ID, Course_Name, Date_Attained, Expiry_Date) VALUES (?, ?, ?, ?)",
                                (employee_id, course_name, date_attained, expiry_date))
                    flash('Course added successfully!', 'hr_employee_add_course_error')
            else:
                flash('All fields are required except Expiry_Date.', 'hr_employee_add_course_error1')

            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None
            }
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }


            option = 'update_course'
            Semp = employee_id
            content = 2

        if action == 'AddAsset':
            employee_id = request.form.get('employee_id7')
            asset_type = request.form.get('selected_asset')
            model = request.form.get('Model')
            serial_number = request.form.get('S_N')
            date_issued = request.form.get('Date_Issued')
            date_returned = request.form.get('Date_Returned')
            Semp_code = get_department_code_by_username(employee_id)

            # Insert into issued_assets table
            db = get_database()
            cursor = db.cursor()
            cursor.execute('INSERT INTO issued_assets (Employee_ID, Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned) VALUES (?, ?, ?, ?, ?, ?)', (employee_id, asset_type, date_issued, model, serial_number, date_returned))
            flash('Asset added successfully!', 'employee_asset_add_success')
            # Update status of asset to 'Issued' in assets table
            cursor.execute('UPDATE assets SET status = ? WHERE S_N = ?', ('Issued', serial_number))
            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (employee_id,))
            emp_data = cursor.fetchone()
            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None }
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

                
            
            # emp_data = cursor.fetchone()
            option = 'update_asset'
            Semp = employee_id
            content = 2
            db.commit()
            
        if action == 'deleteCourse':
            employee_id = request.form.get('employee_id7')
            # print("Delete ................................................Course button clicked.")
            # Handle the course deletion logic
            form_type = 'delete_courses'
            selected_courses = request.form.getlist('selected_courses[]')
            # print("...............selected_courses................",selected_courses)
            Semp_code = get_department_code_by_username(employee_id)
            for course_id in selected_courses:
                course_name = request.form.get(f'course_name_{course_id}')
                # print("...............employee_id....course_name............",employee_id,course_name)
                cursor.execute("DELETE FROM attended_courses WHERE Employee_ID = ? AND Course_Name = ?", (employee_id, course_name))

            db.commit()
            flash('Course Deleted successfully!', 'employee_course_update_success')

            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None  }
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (employee_id,))
            emp_data = cursor.fetchone()

            option = 'update_course'
            Semp = employee_id
            content = 2

        if action == 'deleteAsset':

            employee_id = request.form.get('employee_id77')
            selected_assets = request.form.getlist('selected_assets[]')
            Semp_code = get_department_code_by_username(employee_id)

            # Iterate through selected assets to update or insert records
            for asset_id in selected_assets:
                serial_number = request.form.get(f'serial_number_{asset_id}')
                cursor.execute("DELETE FROM issued_assets WHERE Employee_ID = ? AND Serial_Number = ?", (employee_id, serial_number))
                cursor.execute('UPDATE assets SET status = ? WHERE S_N = ?', ('Open', serial_number))
            flash('Asset Deleted successfully!', 'employee_asset_update_success')
             
            # Query to fetch all courses and their attendance details for the given employee
            query = """ SELECT c.id, c.Course_Name, ac.Date_Attained, ac.Expiry_Date FROM courses c LEFT JOIN attended_courses ac ON c.Course_Name = ac.Course_Name AND ac.Employee_ID = ? ORDER BY c.id DESC """
            cursor = db.execute(query, (employee_id,))
            courses = cursor.fetchall()

            # Create the courses_dict directly from the query result
            courses_dict = {
                course_name: { 'course_id': course_id, 'date_attained': date_attained,'expiry_date': expiry_date,'employee_id': employee_id, 'course_name': course_name }
                for course_id, course_name, date_attained, expiry_date in courses
                if date_attained is not None or expiry_date is not None }
            
            # Convert the dictionary to a list of dictionaries as required
            courses = [ { 'id': details['course_id'], 'Course_Name': course_name, 'Date_Attained': details['date_attained'], 'Expiry_Date': details['expiry_date'] }for course_name, details in courses_dict.items()]

            # Fetch all assets
            cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
            all_assets = cursor.fetchall()
            cursor.execute('SELECT Asset_Type, Date_Issued, Model, Serial_Number, Date_Returned FROM issued_assets WHERE Employee_ID = ?', (employee_id,))
            issued_assets = cursor.fetchall()
            # Create a dictionary with issued assets that have Date_Issued or Date_Returned
            for issued_asset in issued_assets:
                asset_type, date_issued, model, serial_number, date_returned = issued_asset
                if date_issued or date_returned:  # Check if either Date_Issued or Date_Returned is not None
                    for course in all_assets:
                        asset_id, Asset_Name, Model, S_N = course[0], course[1], course[2], course[3]
                        if Asset_Name == asset_type and model == Model and serial_number == S_N:
                            asset_dict[Asset_Name] = { 'asset_id': asset_id, 'Asset_Name': Asset_Name,'Model': Model, 'S_N': S_N, 'employee_id': employee_id, 'Date_Issued': date_issued, 'Date_Returned': date_returned }

            cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality, 
                                        Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee, 
                                        Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA, 
                                        Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Emergency_Contact_No
                                FROM employee_details 
                                WHERE display_Name = ?''', (employee_id,))
            emp_data = cursor.fetchone()
            option = 'update_asset'
            Semp = employee_id
            content = 2
            db.commit()

    assect_dict = asset_dict
    courses_dict = courses_dict
    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 
    cursor.execute("SELECT Asset_Name FROM assets WHERE status != 'Issued'")
    asset_names = [row[0] for row in cursor.fetchall()]
    cursor = db.execute('SELECT Course_Name FROM courses ORDER BY id DESC')
    all_courses = [row[0] for row in cursor.fetchall()]
    user_access = get_employee_access_control(user['name'])
    db.commit()
    # print(".............courses_dict..........\n",courses_dict)
    # print(".............assect_dict..........\n",assect_dict)

    return render_template('admin_templates/hr/hr_employee_bio.html',assect_dict = assect_dict, Semp=Semp,courses_dict=courses_dict, usernames=usernames,is_pm=is_pm,department_code=department_code, 
                          user_access=user_access,Semp_code=Semp_code,all_courses=all_courses,asset_names=asset_names,emp_data=emp_data,user_data=user_data,content=content, option=option,user=user)

@app.route('/get_models')
def get_models():
    asset_name = request.args.get('asset_name')
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT Model FROM assets WHERE Asset_Name = ? AND status != 'Issued'", (asset_name,))
    models = [row[0] for row in cursor.fetchall()]
    db.close()
    return jsonify(models)

@app.route('/get_sn')
def get_sn():
    model = request.args.get('model')
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT S_N FROM assets WHERE Model = ? AND status != 'Issued'", (model,))
    sn = cursor.fetchone()[0]
    db.close()

    return sn

@app.route('/get_employee_bio', methods=['POST'])
def get_employee_bio():
    employee_id = request.form.get('employee_id')
    # print("......employee_id.......",employee_id)
    if employee_id:
        # print("......employee_id.......",employee_id)
        # Query the database for employee details
        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM employee_details WHERE Employee_ID = ?", (employee_id,))
        employee = cursor.fetchone()
        db.close()

        if employee:
            employee_dict = dict(employee)
            # print("......employee_dict.......",employee_dict)
            return jsonify(employee_dict)
        else:
            return jsonify({'error': 'Employee not found'})

    return jsonify({'error': 'Invalid request'})

@app.route('/hr_trade', methods=['GET', 'POST'])
def hr_trade():  
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])


    if request.method == 'POST':
        employee = request.form.get('employee')
        trade = request.form.get('trade')


        work_descriptions = request.form.getlist('descriptions') 
        # Print out received data
        print(f"Employee: {employee}")
        print(f"Trade: {trade}")

        # Process the received data for descriptions
        for description in work_descriptions:
            print(f"{description}: Selected")




    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 


    cursor.execute("SELECT * FROM resource_type")
    rows = cursor.fetchall()
    # Get column headers (designations), excluding 'id' and 'description'
    trade_values = [desc[0] for desc in cursor.description][2:]

    table_data = {}
    for row in rows:
        work_desc = row[1]  # Work description
        table_data[work_desc] = {
            col: row[i + 2] for i, col in enumerate(trade_values)
        }
    work_description = list(table_data.keys())
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/hr/hr_trade.html',work_description=work_description,usernames=usernames,trade_values = trade_values, user=user,user_access=user_access,department_code=department_code)

@app.route('/fetch_descriptions', methods=['POST'])
def fetch_descriptions():
    trade = request.json.get('trade')
    print("........trade.........",trade)
    if not trade:
        return jsonify({"error": "No trade selected"}), 400

    # Query the database for work descriptions where the selected trade is 'On'
    db = get_database()
    cursor = db.cursor()
    query = f"SELECT description FROM resource_type WHERE {trade} = 'On'"
    cursor.execute(query)
    rows = cursor.fetchall()
    # Extract descriptions from the query result
    descriptions = [row['description'] for row in rows]
    return jsonify({"descriptions": descriptions})

##----------------------------------------------------ACCOUNTS------------------------------------------------------------------------------------------------------------


@app.route('/accounts')
def accounts():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])


    cursor.execute("""SELECT status, COUNT(*) FROM payment_request GROUP BY status """)
    pay_count = cursor.fetchall()
    payment_status_count = [{'status': row[0], 'count': row[1]} for row in pay_count]
    print(payment_status_count)

    cursor.execute("""SELECT status, COUNT(*) FROM claims GROUP BY status """)
    claim_count = cursor.fetchall()
    claim_status_count = [{'status': row[0], 'count': row[1]} for row in claim_count]
    print(claim_status_count)

    cursor.execute("""SELECT status, COUNT(*) FROM created_invoice GROUP BY status """)
    inv_count = cursor.fetchall()
    invoice_status_count = [{'status': row[0], 'count': row[1]} for row in inv_count]
    print(invoice_status_count)

    cursor.execute("""SELECT claim_by, status, COUNT(*) FROM claims GROUP BY claim_by, status """)
    claim_status_by_user = cursor.fetchall()

    claim_by_status = [{'claim_by': row[0], 'status': row[1], 'count': row[2]} for row in claim_status_by_user]

    # Transform to nested dict
    transformed_claim_by_data = {}
    for item in claim_by_status:
        person = item['claim_by']
        status = item['status']
        count = item['count']
        if person not in transformed_claim_by_data:
            transformed_claim_by_data[person] = {}
        transformed_claim_by_data[person][status] = count



    # Execute the query
    cursor.execute(""" SELECT
            v.Vehicle_number AS vehicle_no,
            SUM(CASE WHEN ci.Category = 'Loan' THEN ci.total ELSE 0 END) AS Loan,
            SUM(CASE WHEN ci.Category = 'Fuel' THEN ci.total ELSE 0 END) AS Fuel,
            SUM(CASE WHEN ci.Category = 'Parking' THEN ci.total ELSE 0 END) AS Parking,
            SUM(CASE WHEN ci.Category = 'Toll' THEN ci.total ELSE 0 END) AS Toll,
            SUM(CASE WHEN ci.Category = 'Maintenance' THEN ci.total ELSE 0 END) AS Maintenance
        FROM vehicle v
        LEFT JOIN claimed_items ci ON v.Vehicle_number = ci.itemname
            AND ci.Category IN ('Loan', 'Fuel', 'Parking', 'Toll', 'Maintenance')
        GROUP BY v.Vehicle_number
    """)

    # Fetch results and compute total
    rows = cursor.fetchall()
    vehicle_expenses = [
        { 'vehicle_no': row[0], 'Loan': round(row[1], 2), 'Fuel': round(row[2], 2), 'Parking': round(row[3], 2), 'Toll': round(row[4], 2), 
        'Maintenance': round(row[5], 2), 'Total': round(sum(row[1:6]), 2) }
        for row in rows]
    print(vehicle_expenses)

    return render_template('admin_templates/accounts/ac_index.html',user_access=user_access, user=user, department_code=department_code,
                               payment_status_count=payment_status_count,
    claim_status_count=claim_status_count,
    invoice_status_count=invoice_status_count,
    claim_by_chart_data=transformed_claim_by_data,
    vehicle_expenses=vehicle_expenses)

from flask import Flask, session, redirect, url_for, render_template, send_file
import pandas as pd
import sqlite3
from io import BytesIO

@app.route('/ac_suppliers_del', methods=['GET'])
@login_required
def ac_suppliers_del():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    id = request.args.get('id')
    db = get_database()
    db.execute("DELETE FROM vendors_details WHERE id = ?", (id,))
    db.commit()
    
    flash('Client details deleted successfully', 'success')
    return redirect(url_for('vendor'))

@app.route('/client_details', methods=["POST", "GET"])
@login_required
def client_details():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM client_details ORDER BY id DESC')
    client_details = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])


    if request.method == "POST":

        if 'Delete' in request.form:
            # print("...................in the delete form")
            clientdata = request.form.getlist('clientdata[]')
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in clientdata:
                    claim_id = claim_str.split('|')[0]
                    # print("...............id............", claim_id)
                    cursor.execute('DELETE FROM client_details WHERE id = ?', (claim_id,))

                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            return redirect(url_for('client_details'))
            
        Client_code = request.form['Client_code']
        reg_no = request.form['reg_no']
        company_name = request.form['company_name']
        display_name = request.form['display_name']
        fax = request.form['fax']
        office_no = request.form['office_no']
        website = request.form['website']
        billing_address1  = request.form['billing_address1'] 
        billing_address2  = request.form['billing_address2']
        billing_city      = request.form['billing_city']
        billing_postcode  = request.form['billing_postcode']   
        billing_country   = request.form['billing_country']
        billing_state     = request.form['billing_state']
        delivery_address1 = request.form['delivery_address1']   
        delivery_address2 = request.form['delivery_address2']
        delivery_city     = request.form['delivery_city']   
        delivery_postcode = request.form['delivery_postcode']
        delivery_country  = request.form['delivery_country']
        delivery_state    = request.form['delivery_state']
        contact1 = request.form['contact1']
        email1 = request.form['email1']
        mobile1 = request.form['mobile1']
        contact2 = request.form['contact2']
        email2 = request.form['email2']
        mobile2 = request.form['mobile2']
        contact3 = request.form['contact3']
        email3 = request.form['email3']
        mobile3 = request.form['mobile3']
        industry_type = request.form['Industry_type']

        cursor = db.execute('SELECT Client_code FROM client_details ORDER BY id DESC LIMIT 1')
        max_client_code_row = cursor.fetchone()

        if max_client_code_row:
            max_client_code = max_client_code_row[0]
            numeric_part = int(max_client_code.split('-')[-1])
            new_numeric_part = numeric_part + 1
        else:
            new_numeric_part = 1  
        new_client_code = f'C - {new_numeric_part:04d}'

        try:
            # Check if the Client_code already exists
            cursor.execute('SELECT id FROM client_details WHERE Client_code = ?', (Client_code,))
            existing_client = cursor.fetchone()

            if existing_client:
                # Update existing record
                cursor.execute( '''UPDATE client_details SET reg_no = ?, company_name = ?, display_name = ?, fax = ?, office_no = ?, website = ?, billing_address1 = ?,
                                billing_address2 = ?, billing_city = ?, billing_postcode = ?, billing_country = ?, billing_state = ?, delivery_address1 = ?, 
                               delivery_address2 = ?, delivery_city = ?, delivery_postcode = ?, delivery_country = ?, delivery_state = ?, contact1 = ?,
                                email1 = ?, mobile1 = ?, contact2 = ?, email2 = ?, mobile2 = ?, contact3 = ?, email3 = ?, mobile3 = ?, industry_type = ? WHERE Client_code = ?''',
                    [reg_no, company_name, display_name, fax, office_no, website, billing_address1, billing_address2, billing_city, billing_postcode, 
                     billing_country, billing_state, delivery_address1, delivery_address2, delivery_city, delivery_postcode, delivery_country, delivery_state,
                       contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, industry_type, Client_code])
            else:
                # Insert new record
                cursor.execute( '''INSERT INTO client_details (Client_code, reg_no, company_name, display_name, fax, office_no, website, billing_address1,
                                billing_address2, billing_city, billing_postcode, billing_country, billing_state, delivery_address1, delivery_address2,
                                  delivery_city, delivery_postcode, delivery_country, delivery_state, contact1, email1, mobile1, contact2, email2, mobile2,
                                    contact3, email3, mobile3,industry_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    [new_client_code, reg_no, company_name, display_name, fax, office_no, website, billing_address1, billing_address2, billing_city,
                      billing_postcode, billing_country, billing_state, delivery_address1, delivery_address2, delivery_city, delivery_postcode, 
                      delivery_country, delivery_state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3,industry_type])
            
            db.commit()
            flash(f"Client details for '{company_name}' have been updated/added successfully.", 'success')

        except sqlite3.IntegrityError as e:
            db.rollback()
            flash(f"Failed to update/add client details: {str(e)}", 'error')
        cursor = db.execute('SELECT * FROM client_details ORDER BY id DESC')
        client_details = cursor.fetchall()
        cursor = db.execute('SELECT Client_code FROM client_details ORDER BY id DESC LIMIT 1')
        max_client_code = cursor.fetchone()[0]

        # Extract the numeric part and increment
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1

        # Format the new Client_code with leading zeros
        new_client_code = f'C - {new_numeric_part:04d}'
        user_access = get_employee_access_control(user['name'])
        return render_template('admin_templates/accounts/client_details.html',user_access=user_access, user=user,client_details=client_details,
                               department_code=department_code)
   
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/accounts/client_details.html',user_access=user_access, user=user,client_details=client_details,
                           department_code=department_code)

@app.route('/vendor', methods=["POST", "GET"])
@login_required
def vendor():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM vendors_details ORDER BY id DESC')
    vendors = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
    max_client_code_row = cursor.fetchone()

    if max_client_code_row:
        max_client_code = max_client_code_row[0]
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1
    else:
        new_numeric_part = 1  

    new_vendor_code = f'V - {new_numeric_part:04d}'

    if request.method == "POST":

        if 'Delete' in request.form:
            vendordata = request.form.getlist('vendordata[]')
            db = get_database()
            cursor = db.cursor()
            try:
                for claim_str in vendordata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM vendors_details WHERE id = ?', (claim_id,))
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            return redirect(url_for('vendor'))
        
        vendor_code = request.form['vendor_code']
        reg_no = request.form['reg_no']
        company_name = request.form['company_name']
        display_name = request.form['display_name']
        office_no = request.form['office_no']
        website = request.form['website']
        billing_address1 = request.form['billing_address1']
        billing_address2 = request.form['billing_address2']
        city = request.form['city']
        postcode = request.form['postcode']
        country = request.form['country']
        state = request.form['state']
        contact1 = request.form['contact1']
        email1 = request.form['email1']
        mobile1 = request.form['mobile1']
        contact2 = request.form['contact2']
        email2 = request.form['email2']
        mobile2 = request.form['mobile2']
        contact3 = request.form['contact3']
        email3 = request.form['email3']
        mobile3 = request.form['mobile3']
        bank_name = request.form['bank_name']
        tax_id = request.form['tax_id']
        branch_details = request.form['branch_details']
        currency = request.form['currency']
        pay_terms = request.form['pay_terms']
        account_no = request.form['account_no']
        swift = request.form['swift']
        ifsc = request.form['ifsc']
        product_catgory = request.form['Product_Category']
        brand = request.form['Brands']
        Details = request.form['Details']

        try:
            # Check if vendor code exists
            cursor.execute('SELECT id FROM vendors_details WHERE vendor_code = ?', (vendor_code,))
            existing_vendor = cursor.fetchone()

            if existing_vendor:
                # Update existing vendor
                vendor_id = existing_vendor[0]
                cursor.execute( '''UPDATE vendors_details SET reg_no = ?, company_name = ?, display_name = ?, office_no = ?, website = ?, billing_address1 = ?,
                                billing_address2 = ?, city = ?, postcode = ?, country = ?, state = ?, contact1 = ?, email1 = ?, mobile1 = ?, contact2 = ?, email2 = ?,
                                mobile2 = ?, contact3 = ?, email3 = ?, mobile3 = ?, bank_name = ?, tax_id = ?, branch_details = ?, currency = ?, pay_terms = ?, 
                               account_no = ?, swift = ?, ifsc = ?, product_catgory = ?, brand = ?, Details= ?  WHERE id = ?''',
                                [reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, 
                                 contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency,
                                   pay_terms, account_no, swift, ifsc,product_catgory, brand, Details, vendor_id] )
                db.commit()
                flash(f"Vendor details for '{company_name}' have been updated.", 'success')
            else:
                # Insert new vendor
                cursor.execute(
                    '''INSERT INTO vendors_details (vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city,
                      postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, 
                      currency, pay_terms, account_no, swift, ifsc, product_catgory, brand, Details) VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    [vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1,
                      email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, 
                      swift, ifsc,product_catgory, brand, Details])
                db.commit()
                flash(f"Vendor details for '{company_name}' have been successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add/update vendor details. Please try again.", 'error')

        return redirect(url_for('vendor'))
    
    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT COUNT(*) FROM vendors_details")
    total_vendors = cursor.fetchone()[0]
    return render_template('admin_templates/accounts/vendor.html',user_access=user_access, user=user,vendors=vendors,department_code=department_code,
                           total_vendors=total_vendors,new_vendor_code=new_vendor_code)

@app.route('/delete_client', methods=['GET'])
@login_required
def delete_client():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    id = request.args.get('id')
    db = get_database()
    db.execute("DELETE FROM client_details WHERE id = ?", (id,))
    db.commit()
    
    flash('Client details deleted successfully', 'success')
    return redirect(url_for('client_details'))

@app.route('/delete_vendor', methods=['GET'])
@login_required
def delete_vendor():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    id = request.args.get('id')
    db = get_database()
    db.execute("DELETE FROM vendors_details WHERE id = ?", (id,))
    db.commit()
    
    flash('Client details deleted successfully', 'success')
    return redirect(url_for('vendor'))

def new_inv_pdf(data_dict, total_sum_str, gst_amount_str, final_total_str, gst, inv_details,po_value ,previous_calim ,balance_calim,calim_history,
                Exchange_GST,comments_on_pdf ):

    # Convert sqlite3.Row to dictionary
    if isinstance(inv_details, sqlite3.Row):
        inv_details = dict(inv_details)
    
    if isinstance(data_dict, sqlite3.Row):
        data_dict = dict(data_dict)
    if isinstance(data_dict, list):
        data_dict = [
            {k: normalize_text(v) if k not in ['Part_No', 'item'] else normalize_text(v) for k, v in item.items()} for item in data_dict]
    else:
        data_dict = {k: normalize_text(v) if k not in ['Part_No', 'item'] else normalize_text(v) for k, v in data_dict.items()}
    
    inv_details = {k: normalize_text(v) for k, v in inv_details.items()}
    pdf_output = BytesIO()

    pdf = INVPDF(data_dict, total_sum_str, gst_amount_str, final_total_str, gst, inv_details,po_value ,previous_calim ,balance_calim,
                 calim_history,Exchange_GST,comments_on_pdf )  # Pass the required arguments
    pdf.add_page()  # This opens a new page to start drawing content
    pdf.body()

    pdf_output.write(pdf.output(dest='S').encode('latin1'))  # Write the output to the BytesIO object
    pdf_output.seek(0)  # Seek to the beginning of the BytesIO object

    return pdf_output  # Return the BytesIO object containing the PDF

class INVPDF(FPDF):

    def __init__(self, data_dict, total_sum_str,gst_amount_str,final_total_str,gst, inv_details, po_value ,previous_calim ,balance_calim,calim_history,Exchange_GST,comments_on_pdf, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inv_details = inv_details
        self.final_total_str = final_total_str
        self.total_sum_str = total_sum_str
        self.gst_amount_str = gst_amount_str
        self.po_value = po_value
        print("......................po_value..",po_value)
        self.previous_calim = previous_calim
        self.balance_calim = balance_calim
        self.gst = gst
        self.data_dict = data_dict
        self.max_y = 0
        self.page_height = 292 
        self.calim_history = calim_history
        self.Exchange_GST = Exchange_GST 
        self.comments_on_pdf = comments_on_pdf 
        self.last_page = None  
        self.alias_nb_pages()  

    def header(self):
        self.set_line_width(0.4) 
        self.rect(2, 2 , 205, 292)

        image_path = os.path.join('static', 'CENTROID Logo.jpg')  # Replace with your actual static path
        # image_path = os.path.join('/home/CES/mysite/static', 'CENTROID Logo.jpg')
        self.image(image_path, 155, 5, 50, 8) 
        self.set_font('helvetica', '', 12)
        # Company details aligned to the leftmost side
        self.set_xy(2, 5)  # Start text at the leftmost side of the page
        self.set_font("Arial", size=10)  # Adjust the size as needed
        # Company details
        self.cell(0, 6, 'Centroid Engineering Solutions Pte Ltd', ln=True)
        self.set_x(2)  # Reset x-coordinate after each line break
        self.cell(0, 6, 'Co Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'GST Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, '11, Woodlands Close, #07-10', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'Singapore - 737853', ln=True)

        self.set_xy(25, 28)  # Adjust position of the title (center between details and logo)
        self.set_font('helvetica', 'B', 20)  # Title in bold
        self.cell(0, 10, 'TAX INVOICE', ln=True, align='C')  # Title in the center

        self.line(2, 39, 207, 39)  # Line from x=10 to x=200 at y=40

        # print("...........inv_details...............",self.inv_details)

        from datetime import datetime
        if 'inv_date' in self.inv_details:
            try:
                inv_date = datetime.strptime(self.inv_details['inv_date'], '%Y-%m-%d')
                formatted_inv_date = inv_date.strftime('%d-%m-%Y')
            except ValueError:
                formatted_inv_date = self.inv_details['inv_date']  # Fallback if date parsing fails
        
        else:
            print("⚠️ Warning: 'inv_date' key is missing in self.inv_details.")
            formatted_inv_date = "Unknown"  # Handle missing key gracefully

        # Client Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 40)
        self.cell(0, 6, 'Bill To', ln=False)
        self.set_xy(19, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(21, 40)
        self.cell(0, 6, self.inv_details['B_client'], ln=True)

        # Client Address
        self.set_x(21)
        self.cell(0, 6, self.inv_details['bill_to_line2'], ln=True)
        self.set_x(21)
        self.cell(0, 6, self.inv_details['bill_to_line3'], ln=True)

        # Attn Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 58)
        self.cell(0, 6, 'Attn', ln=False)
        self.set_xy(19, 58)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.inv_details['attn'], ln=True)

        # PO Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(145, 40)
        self.cell(0, 6, 'Invoice No', ln=False)
        self.set_xy(145, 46)
        self.cell(0, 6, 'Date', ln=False)
        self.set_xy(145, 52)
        self.cell(0, 6, 'PO No', ln=False)
        self.set_xy(145, 58)
        self.cell(0, 6, 'Page', ln=False)

        # PO Values
        self.set_font("helvetica", "B", 10)
        self.set_xy(163, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(165, 40)
        self.cell(0, 6, self.inv_details['inv_no'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(163, 46)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(165, 46)
        # from datetime import datetime
        # Convert the date format
        formatted_date = datetime.strptime(self.inv_details['inv_date'], "%Y-%m-%d").strftime("%d-%m-%Y")
        self.cell(0, 6, formatted_date, ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(163, 52)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(165, 52)
        self.cell(0, 6, self.inv_details['po_number'][:20], ln=True)


        self.set_font("helvetica", "B", 10)
        self.set_xy(163, 58)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(165, 58)
        # self.cell(0, 6, '1 of 1', ln=True)
        self.cell(0, 6, f'{self.page_no()} of {{nb}}', ln=True)  
        self.line(2, 64, 207, 64) 

        # Delivery Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 65)
        self.cell(0, 6, 'Ship To', ln=False)
        self.set_xy(19, 65)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.inv_details['D_client'], ln=True)

        # Delivery Address
        self.set_xy(21, 71)
        self.cell(0, 6, self.inv_details['delivary_to_line2'], ln=True)
        self.set_xy(21, 77)
        self.cell(0, 6, self.inv_details['delivary_to_line3'], ln=True)

        # Contact Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(163, 65)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(145, 65)
        self.cell(0, 6, 'Terms', ln=False)

        # Delivery Values
        self.set_font("helvetica", "", 10)
        self.set_xy(165, 65)
        terms_text = self.inv_details['payment_terms']

        if terms_text != "COD":
            terms_text = f"{self.inv_details.get('Terms', '')}  {terms_text}"

        self.cell(0, 6, terms_text, ln=True)
        self.line(2, 83, 207, 83)  # Line from x=10 to x=200 at y=40
        # Column widths
        item_width = 10
        description_width = 85
        qty_width = 20
        unit_price_width = 25
        total_price_width = 30
        # Item table heading
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 83)
        self.cell(item_width, 6, 'Item', ln=False)

        self.set_xy(65, 83)
        self.cell(description_width, 6, 'Description', ln=False)

        self.set_xy(135, 83)
        self.cell(qty_width, 6, 'Qty', ln=False)

        self.set_xy(151, 83)
        self.cell(unit_price_width, 6, 'Unit Price', ln=False)

        self.set_xy(183, 83)
        self.cell(total_price_width, 6, 'Total Price', ln=False)

        self.line(2, 90, 207, 90)  # Line from x=10 to x=200 at y=40
        self.line(2, 288, 207, 288) # footer above line

    def footer(self):
        self.set_xy(60, 289)
        self.cell(0, 6, 'Centroid Engineering Solution - Tax Invoice.', ln=False)
        if self.page_no() == self.last_page:  # Check if we're far enough from the page bottom
            self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
            self.set_font("helvetica", "B", 10)
            self.set_font("helvetica", "", 10)

            # Bank Details Section
            self.set_xy(2, 231)  # Adjust Y position for Bank details
            self.cell(0, 6, 'Bank', ln=True)  # Print Bank heading
            self.set_xy(17, 231)
            self.cell(0, 6, ':', ln=False)
            self.set_font("helvetica", "", 10)
            self.set_xy(21, 231)
            self.cell(0, 6, self.inv_details['bank_name'], ln=True)

            self.set_xy(2, 237)  # Adjust Y position
            self.cell(0, 6, 'Branch', ln=True)  # Print Branch heading
            self.set_xy(17, 237)
            self.cell(0, 6, ':', ln=False)
            self.set_font("helvetica", "", 10)
            self.set_xy(21, 237)
            self.cell(0, 6, str(self.inv_details.get('brnach', '')), ln=True)

            self.set_xy(2, 243)  # Adjust Y position
            self.cell(0, 6, 'Swift', ln=True)  # Print Swift heading
            self.set_xy(17, 243)
            self.cell(0, 6, ':', ln=False)
            self.set_font("helvetica", "", 10)
            self.set_xy(21, 243)
            # self.cell(0, 6, self.inv_details['swift'], ln=True)
            self.cell(0, 6, str(self.inv_details.get('swift', '')), ln=True)

            self.set_xy(2, 249)  # Adjust Y position
            self.cell(0, 6, 'Acc No', ln=True)  # Print Account Number heading
            self.set_xy(17, 249)
            self.cell(0, 6, ':', ln=False)
            self.set_font("helvetica", "", 10)
            self.set_xy(21, 249)
            # self.cell(0, 6, self.inv_details['bank_acc_no'], ln=True)
            self.cell(0, 6, str(self.inv_details.get('bank_acc_no', '')), ln=True)

            if self.Exchange_GST:    
                self.set_font("helvetica", "B", 10)
                self.set_xy(2, 256)  # Adjust Y position
                self.cell(0, 6, 'For GST Purpose Only', ln=True)  # Print Account Number heading
                self.set_font("helvetica", "", 10)
                self.line(2, 262, 80, 262) # total table line one from above 

                self.set_xy(2, 263)  # Adjust Y position
                self.cell(0, 6, 'Exchange Rate to SGD', ln=True)  # Print Swift heading
                self.set_xy(47, 263)
                self.cell(0, 6, ':', ln=False)
                self.set_xy(55, 263)
                exchange_rate = self.inv_details.get('exchange_rate', '0')  # Default to '0' if empty or None
                try:
                    exchange_rate = "{:,.2f}".format(float(exchange_rate))
                except ValueError:
                    exchange_rate = "0.00"  # Default to '0.00' if conversion fails

                self.cell(0, 6, '$ ' + exchange_rate, ln=True)


                self.set_xy(2, 269)  # Adjust Y position
                self.cell(0, 6, 'Total Excl. GST (SGD)', ln=True)  # Print Swift heading
                self.set_xy(47, 269)
                self.cell(0, 6, ':', ln=False)
                self.set_xy(55, 269)
                # excl_gst = "{:,.2f}".format(float(str(self.inv_details['amount'] * self.inv_details['exchange_rate']).replace(',', '')))
                excl_gst_value = float(self.inv_details['amount']) * float(exchange_rate)
                excl_gst = "{:,.2f}".format(excl_gst_value)  
                self.cell(0, 6, "$ " + excl_gst, ln=True)
      

                self.set_xy(2, 275)  # Adjust Y position
                self.cell(0, 6, f"Std Rated {self.gst}% GST (SGD)", ln=True)  # Print Swift heading
                self.set_xy(47, 275)
                self.cell(0, 6, ':', ln=False)
                self.set_xy(55, 275)
                standared_rate_gst = "{:,.2f}".format(float(exchange_rate) * float(self.gst_amount_str.replace(',', '')))

                self.cell(0, 6, "$ " + standared_rate_gst , ln=True)
                self.line(2, 281, 80, 281) # total table line one from above 


                self.set_xy(2, 282)  # Adjust Y position
                self.cell(0, 6, 'Total Incl. GST (SGD)', ln=True)  # Print Swift heading
                self.set_xy(47, 282)
                self.cell(0, 6, ':', ln=False)
                self.set_xy(55, 282)
                # Ensure values are floats before performing arithmetic
                standared_rate_gst = float(exchange_rate) * float(self.gst_amount_str.replace(',', ''))
                exchange_total_value = excl_gst_value  + standared_rate_gst
                exchange_total_value = "{:,.2f}".format(exchange_total_value)

                self.cell(2, 6, "$ " + exchange_total_value, ln=True)


            # self.cell(2, 6, "$ " + exchange_total_value, ln=True)

            # self.line(2, 285, 207, 285) # footer above line

    def body(self):
        self.ln(10)  # Add some space
        initial_y_position = max(self.get_y(), 10)  # Ensure Y doesn't go too high
        self.set_y(initial_y_position)  # Move the cursor safely
        self.set_font("helvetica", "", 10)

        item_counter = 1
        for item in self.data_dict:


            description_height = 0
            item_width = 10
            description_width = 85
            qty_width = 20
            unit_price_width = 25
            total_price_width = 30
            is_heading = not item['total'] or float(item['total'].replace(',', '')) == 0

            self.set_font("helvetica", "", 10)

            if self.get_y() >= 275:  
                self.line(2 + item_width, 83, 2 + item_width, 288)  # Vertical line
                self.line(46 + description_width, 83, 46 + description_width, 288)  # Vertical line
                self.line(127 + qty_width, 83, 127 + qty_width, 288)  # Vertical line
                self.line(150 + unit_price_width, 83, 150 + unit_price_width, 288)  # Vertical line
                self.line(177 + total_price_width, 83, 177 + total_price_width, 288)  # Vertical line
                self.add_page()
                self.header()  # Print header again on the new page
                self.set_y(94)  # Reset Y to a proper starting point (adjust as needed)

            current_y = self.get_y()

            if item['total']:

                description_height = self.get_string_width(item['item']) / (description_width + 30) * 6  # Approximate height calculation
                if self.get_y() + description_height >= 275:
                    self.line(2 + item_width, 83, 2 + item_width, 288)  # Vertical line
                    self.line(46 + description_width, 83, 46 + description_width, 288)  # Vertical line
                    self.line(127 + qty_width, 83, 127 + qty_width, 288)  # Vertical line
                    self.line(150 + unit_price_width, 83, 150 + unit_price_width, 288)  # Vertical line
                    self.line(177 + total_price_width, 83, 177 + total_price_width, 288)  # Vertical line
                    self.add_page()
                    self.header()  # Print header again on the new page
                    self.set_y(94)  # Reset Y to a proper starting point (adjust as needed)
                
                current_y = self.get_y()
                self.set_font("helvetica", "", 10)

                self.set_xy(4, current_y)  # Reset x-coordinate for Item
                self.set_font("helvetica", "", 10)
                self.cell(item_width, 6, str(item_counter), ln=False)
                self.set_xy(12, current_y)  # Reset x-coordinate for Part No
                self.set_xy(2 + item_width, current_y)
                description_height = self.multi_cell(description_width + 30, 6, item['item'], 0, 'L')  # Wrap the description
                description_height = self.get_y() - current_y  # Calculate actual height used by description

                # Print UOM, Qty
                self.set_xy(38 + item_width + description_width, current_y)  # Reset x-coordinate for UOM
                self.cell(qty_width, 6, item['quantity'], ln=False)  # Qty

                # Remove commas before converting to float
                unit_price_text = f"$ {float(item['Unit_Price'].replace(',', '')):,.2f}"
                unit_price_width1 = self.get_string_width(unit_price_text)

                # Adjust x position for right alignment
                self.set_xy(80 + item_width + description_width - unit_price_width1, current_y)
                self.cell(unit_price_width1, 6, unit_price_text, ln=False, align="R")  # Right-aligned

                # Remove commas before converting to float for total price
                total_price_text = f"$ {float(item['total'].replace(',', '')):,.2f}"
                total_price_width1 = self.get_string_width(total_price_text)

                # Adjust x position for right alignment of Total Price
                self.set_xy(110 + item_width + description_width - total_price_width1, current_y)
                self.cell(total_price_width1, 6, total_price_text, ln=True, align="R")  # Right-aligned

            self.set_y(current_y + max(6, description_height))
            print("......current_y....",current_y)
            item_counter += 1


       
       
        if self.calim_history:   
            print("#######################################......current_y....",current_y)
            current_y = self.get_y()  # <-- this resets to current page's Y position
            self.set_font("helvetica", "B", 10)
            self.set_xy(15, current_y + 20)
            self.cell(0, 6, 'Claim History', ln=False)

            self.set_font("helvetica", "", 10)
            self.set_xy(15, current_y + 26)
            self.cell(0, 6, 'PO Value', ln=False)
            self.set_xy(40, current_y + 26)
            self.cell(0, 6, ':', ln=False)
            self.set_xy(43, current_y + 26)
            self.cell(0, 6, "$ " +self.po_value, ln=True)

            self.set_xy(15, current_y + 32)
            self.cell(0, 6, 'Previous Claim', ln=False)
            self.set_xy(40, current_y + 32)
            self.cell(0, 6, ':', ln=False)
            self.set_xy(43, current_y + 32)
            self.cell(0, 6, "$ " + self.previous_calim, ln=True)

            self.set_xy(15, current_y + 38)
            self.cell(0, 6, 'This Claim', ln=False)
            self.set_xy(40, current_y + 38)
            self.cell(0, 6, ':', ln=False)
            self.set_xy(43, current_y + 38)
            self.cell(0, 6,"$ " + self.total_sum_str, ln=True)

            self.set_xy(15, current_y + 44)
            self.cell(0, 6, 'Balance Claim', ln=False)
            self.set_xy(40, current_y + 44)
            self.cell(0, 6, ':', ln=False)
            self.set_xy(43, current_y + 44)
            self.cell(0, 6, "$ " + self.balance_calim, ln=True)

            current_y += 56  # Leaves some space after the last claim entry

        from textwrap import wrap

        if self.comments_on_pdf:
            self.set_font("helvetica", "B", 10)
            current_y = self.get_y()  # <-- this resets to current page's Y position
            self.set_xy(15, current_y + 10)
            self.cell(0, 6, 'Comments', ln=True)

            self.set_font("helvetica", "", 10)
            comment_text = str(self.inv_details.get('comments', ''))

            # Split based on user-entered line breaks
            lines = comment_text.splitlines()

            self.set_x(15)
            for line in lines:
                # Each original line from textarea is wrapped within your defined width
                self.multi_cell(description_width + 30, 6, line, 0, 'L')
                self.set_x(15)  # Reset X to align all lines properly under "Comments"



        if self.get_y() + 20 >= 275:
            self.line(2 + item_width, 83, 2 + item_width, 288)  # Vertical line
            self.line(46 + description_width, 83, 46 + description_width, 288)  # Vertical line
            self.line(127 + qty_width, 83, 127 + qty_width, 288)  # Vertical line
            self.line(150 + unit_price_width, 83, 150 + unit_price_width, 288)  # Vertical line
            self.line(177 + total_price_width, 83, 177 + total_price_width, 288)  # Vertical line
            self.add_page()
            self.header()  # Print header again on the new page
            self.set_y(94)  # Reset Y to a proper starting point (adjust as needed)


        footer_y = self.get_y() + 10
        
        if footer_y < 220:
            self.set_y(footer_y)  
        
        else:
            self.line(2 + item_width, 83, 2 + item_width, 288)  # Vertical line
            self.line(46 + description_width, 83, 46 + description_width, 288)  # Vertical line
            self.line(127 + qty_width, 83, 127 + qty_width, 288)  # Vertical line
            self.line(150 + unit_price_width, 83, 150 + unit_price_width, 288)  # Vertical line
            self.line(177 + total_price_width, 83, 177 + total_price_width, 288)  # Vertical line
            self.add_page()  # Add a new page for the footer if there's no space
            self.header()  # Print the header on the new page if needed

        self.line(2 + item_width, 83, 2 + item_width, 230)  # Vertical line
        self.line(46 + description_width, 83, 46 + description_width, 248)  # Vertical line
        self.line(127 + qty_width, 83, 127 + qty_width, 230)  # Vertical line
        self.line(150 + unit_price_width, 83, 150 + unit_price_width, 248)  # Vertical line
        self.line(177 + total_price_width, 83, 177 + total_price_width, 230)  # Vertical line

        self.line(2, 230, 207, 230) # items table  end line 
        self.line(131, 236, 207, 236) # total table line one from above 
        self.line(131, 242, 207, 242) # total table line one from above 
        self.line(131, 248, 207, 248) # total table line one from above 
        # self.line(131, 280, 207, 280) # stamp line
        

        self.set_xy(145, 230)
        self.set_font("helvetica", "B", 10)
        self.cell(total_price_width, 6, f"Amount ({self.inv_details['Currency']})", ln=False)    
        self.set_xy(146, 236)
        self.cell(total_price_width, 6, f"GST ({self.gst}%)", ln=False)
        self.set_xy(145, 242)
        self.cell(total_price_width, 6, f"Total ({self.inv_details['Currency']})", ln=False)

        ces_stamp_img = os.path.join('static', 'ces_stamp.png') 
        # ces_stamp_img = os.path.join('/home/CES/mysite/static', 'ces_stamp.png')
                # Try to add the CES Stamp image
        try:
            self.image(ces_stamp_img, 160, 260, 30)  # Only width is specified, height is auto-scaled.
        except Exception as e:
            print(f"Error loading image {ces_stamp_img}: {e}") 
        self.set_xy(145, 252)
        self.cell(total_price_width, 6, f"for Centroid Engineering Solutions", ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(175, 230)
        self.cell(total_price_width, 6, "$ " + self.total_sum_str, ln=False, align="R")  
        self.set_xy(175, 236)
        self.cell(total_price_width, 6, "$ " + self.gst_amount_str, ln=False, align="R")  
        self.set_xy(175, 242)
        self.cell(total_price_width, 6, "$ " + self.final_total_str, ln=False, align="R")  

        self.last_page = self.page_no()

@app.route('/invoice', methods=["POST", "GET"])
@login_required
def invoice():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT display_name FROM client_details ORDER BY display_name ASC")
    clients = cursor.fetchall()
    cursor.execute("SELECT id,po_number FROM projects ORDER BY id DESC")
    prj_po_list = cursor.fetchall()

    if request.method == "POST":

        inv_Print = request.form.get ('inv_Print')
        invoice_req_id = request.form.get ('invoice_req_id')

        if invoice_req_id:
            paid_amount = request.form.get('paid_amount')
            recv_on = request.form.get('recv_on')
            paid_amount = float(paid_amount) if paid_amount and paid_amount != 'None' else 0.0
            cursor.execute("SELECT total FROM created_invoice WHERE inv_no = ?", (invoice_req_id,))
            result = cursor.fetchone()  
            actual_request_amount = float(result[0]) if result and result[0] is not None else 0.0
            cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM invoice_pay_history WHERE inv_no = ?", (invoice_req_id,))
            past_paid_amount = cursor.fetchone()[0] or 0.0  # Default to 0.0 if it's None
            total_paid = past_paid_amount + paid_amount
            balance = actual_request_amount - total_paid
            if balance == 0:
                pay_status = "Paid"
            elif balance < actual_request_amount:
                pay_status = "Partial"
            else:
                pay_status = "Pending"

            from datetime import datetime
            current_date = datetime.now().strftime('%Y-%m-%d')
            db.execute(''' UPDATE created_invoice SET status = ?, Recent_rec_On = ?, balence = ? WHERE inv_no = ?  ''', 
                    (pay_status, recv_on, balance, invoice_req_id))
            db.execute(''' INSERT INTO invoice_pay_history (inv_no, pay_date, paid_by, amount) VALUES (?, ?, ?, ?) ''',
                    (invoice_req_id, recv_on, user['name'], paid_amount))
            db.commit()

            return redirect(url_for('invoice'))
    
        if inv_Print:
     
            calim_history = request.form.get ('calim_history')
            Exchange_GST = request.form.get ('Exchange_GST')
            comments_on_pdf = request.form.get ('comments_on_pdf')

            cursor.execute('SELECT * FROM created_invoice WHERE inv_no = ?', (inv_Print,))
            inv_details = cursor.fetchone()

            cursor.execute("SELECT po_number FROM created_invoice WHERE inv_no = ?", (inv_Print,))
            invoice = cursor.fetchone()

            if invoice and invoice[0]: 
                po_number = invoice[0]
                cursor.execute("SELECT po_value FROM projects WHERE po_number = ?", (po_number,))
                po_value = cursor.fetchone()


                if po_value:  
                    po_value = po_value[0]  
                else:
                    po_value = 0  
                print("...po_value....1.....",po_value)
                cursor.execute("""
                    SELECT SUM(amount)
                    FROM created_invoice
                    WHERE po_number = ?
                    AND inv_no != ?
                    AND inv_date < ?
                """, (po_number, inv_Print, inv_details['inv_date']))

                previous_calim = cursor.fetchone()[0] or 0
                print("...............inv_details['inv_date'].........",inv_details['inv_date'])
                print(".......previous_calim............",previous_calim)

            else:
                po_value = 0
                previous_calim = 0
            print("...po_value.2........",po_value)
            if isinstance(po_value, str) and po_value.strip() != '':
                print("...po_value...3......",po_value)
                po_value = float(po_value.replace(",", "")) if ',' in po_value else float(po_value)
                print("...po_value...4......",po_value)
            else:
                po_value = po_value # Default to 0 if the value is empty or invalid


            previous_calim = "{:,.2f}".format(previous_calim)  
            # balance_calim = "{:,.2f}".format(po_value - float(str(inv_details['total']).replace(',', '')))
            balance_calim = "{:,.2f}".format(float(po_value) - float(str(inv_details['amount']).replace(',', '')))

            cursor.execute(''' SELECT item, quantity, Unit_Price, total FROM invoice_items WHERE inv_no = ? ''', (inv_Print,))
            inv_items = cursor.fetchall()

            if inv_items:
                data_dict = []
                total_sum = 0
                
                for index, item in enumerate(inv_items):  # Use enumerate to get index and item
                    
                    # Ensure Unit_Price and total are safely converted to float for processing
                    unit_price = float(item[2])
                    total_value = float(item[3])
                    
                    # Format Unit_Price and total_value to international numbering format with 2 decimal places
                    formatted_unit_price = "{:,.2f}".format(unit_price)
                    formatted_total_value = "{:,.2f}".format(total_value)
                    
                    # Safely convert other values to strings
                    item_dict = {
                        'index': str(index + 1),  # Convert index to string
                        'item': str(item[0]),     # Convert item to string
                        'quantity': str(item[1]),  # Convert quantity to string
                        'Unit_Price': formatted_unit_price,  # Use formatted Unit_Price string
                        'total': formatted_total_value,  # Use formatted total string
                    }
                    
                    data_dict.append(item_dict)

                total_sum_str = "{:,.2f}".format(inv_details['amount'])  
                gst_amount_str = "{:,.2f}".format(inv_details['gst_value'])  
                final_total_str = "{:,.2f}".format(inv_details['total']) 
                total_sum = "{:,.2f}".format(total_sum)
                print("...po_value...5......",po_value)

                po_value = "{:,.2f}".format(po_value)
                print("...po_value...6......",po_value)

                pdf_file = new_inv_pdf(data_dict, total_sum_str, gst_amount_str, final_total_str, inv_details['gst_percent'], inv_details,
                                       po_value ,previous_calim ,balance_calim,calim_history,Exchange_GST,comments_on_pdf )

                if pdf_file:
                    db.commit()  
                    return send_file(pdf_file, download_name=f"{inv_details['inv_no']}.pdf", as_attachment=True, mimetype='application/pdf')
            
            else:
                flash("No items found for the selected PO number.")
                return redirect(url_for('invoice'))

        Invoice_date = request.form.get("Invoice_date")
        projectid = request.form.get("po_number")
        prj_id = projectid if projectid else None
        cursor.execute("SELECT po_number FROM projects WHERE id = ?", (projectid,))
        result = cursor.fetchone()
        external_po = request.form.get("External_po")
        po_number = result[0] if result else external_po
        # prj_id = request.form.get("prj_id")
        

        Attn = request.form.get("Attn")
        Terms = request.form.get("Terms")
        time_period = request.form.get("time_period")
        Bill_to = request.form.get("Bill_to")
        Billing_Address_Line1 = request.form.get("Billing_Address_Line2")
        Billing_Address_Line2 = request.form.get("Billing_Address_Line3")
        Delivery_to = request.form.get("Delivery_to")
        Delivery_Address_Line1 = request.form.get("Delivery_Address_Line2")
        Delivery_Address_Line2 = request.form.get("Delivery_Address_Line3")
        B_client = request.form.get("Billing_Address_Line1")
        D_client = request.form.get("Delivery_Address_Line1")
        gst = request.form.get("gst")
        total_amount = request.form.get("total_amount")
        gst_value = request.form.get("gst_value")
        overall_total_amount = request.form.get("overall_total_amount")
        descriptions = request.form.getlist("description[]")
        qtys = request.form.getlist("qty[]")
        unit_prices = request.form.getlist("unit_price[]")
        bank_name = request.form.get("Bank")
        bank_acc_no = request.form.get("Account_No")
        created_date = Invoice_date
        Currency  = request.form.get("Currency")
        exchange_rate = request.form.get("exchange_rate", 1)
        gst = request.form.get("gst")
        swift = request.form.get("Swift")
        brnach = request.form.get("Branch")
        gst_percent = request.form.get("gst_percent")
        Status = 'Open'
        Invoice_No = request.form.get("Invoice_No")
        existing_invoice = cursor.execute("SELECT id FROM created_invoice WHERE inv_no = ?", (Invoice_No,)).fetchone()
        comments = request.form.get("comments")
        print("........Invoice_No..........",Invoice_No)

  
        if existing_invoice:

            cursor.execute("""UPDATE created_invoice SET inv_date = ?, po_number = ?, external_po = ?, 
            attn = ?, payment_terms = ?, bank_name = ?, bank_acc_no = ?, created_by = ?, created_date = ?, bill_to_line1 = ?, 
            bill_to_line2 = ?, bill_to_line3 = ?, delivary_to_line1 = ?, delivary_to_line2 = ?, delivary_to_line3 = ?, status = ?, amount = ?, gst_value = ?, 
            total = ?, Currency = ?, exchange_rate = ?, gst = ?, swift = ?, brnach = ?, Terms = ?, B_client = ?, D_client = ? , balence=?, gst_percent= ?, comments = ?, prj_id = ?
                WHERE inv_no = ?
            """, (Invoice_date, po_number, prj_id, Attn, time_period, bank_name, bank_acc_no, user['name'],
                created_date, Bill_to, Billing_Address_Line1, Billing_Address_Line2, Delivery_to, Delivery_Address_Line1, 
                Delivery_Address_Line2, 'Open', total_amount, gst_value, overall_total_amount, Currency, exchange_rate, gst,swift ,brnach, 
                Terms, B_client, D_client,overall_total_amount, gst_percent,comments,prj_id, Invoice_No))
            db.commit()

            cursor.execute("""DELETE FROM invoice_items WHERE inv_no = ?""", (Invoice_No,))
            db.commit()

            for i in range(len(descriptions)):
                if descriptions[i] and qtys[i] and unit_prices[i]:
                    qty = float(qtys[i])  # Ensure it's a number
                    unit_price = float(unit_prices[i])  # Ensure it's a number
                    total = qty * unit_price  # Compute total

                    cursor.execute("""
                        INSERT INTO invoice_items (inv_no, po_number, prj_id, item, quantity, Unit_Price, total) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (Invoice_No, po_number, prj_id, descriptions[i], qty, unit_price, total))

            db.commit()
            return redirect(url_for("invoice"))
        
        else:
            from datetime import datetime
            if Invoice_date:
                invoice_year = datetime.strptime(Invoice_date, "%Y-%m-%d").year  
                invoice_year = str(invoice_year)[-2:] 
            else:
                invoice_year = str(datetime.now().year)[-2:]  

            latest_invoice = db.execute("SELECT inv_no FROM created_invoice ORDER BY id DESC LIMIT 1").fetchone()

            if latest_invoice:
                last_inv_no = latest_invoice[0]  # Get the last invoice number
                last_inv_id = int(last_inv_no.split("-")[2])  # Extract the numeric part after the last '-'
                new_invoice_no = f"I-{invoice_year}-{last_inv_id + 1}"  # Increment from the last number
            
            else:
                new_invoice_no = f"I-{invoice_year}-2035"  # Start from 2036 if no records exist

            Invoice_No = new_invoice_no

            cursor.execute("""
                INSERT INTO created_invoice (inv_no, inv_date, po_number, external_po, attn, payment_terms, bank_name, bank_acc_no, 
                                    created_by, created_date, bill_to_line1, bill_to_line2, bill_to_line3, 
                                    delivary_to_line1, delivary_to_line2, delivary_to_line3, status, amount, gst_value, total, Currency, 
                        exchange_rate, gst,swift ,brnach, Terms, B_client, D_client, Status,balence,gst_percent,comments,prj_id ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (Invoice_No, Invoice_date, po_number, prj_id, Attn, time_period, bank_name, bank_acc_no, user['name'],
                created_date, Bill_to, Billing_Address_Line1, Billing_Address_Line2, Delivery_to, Delivery_Address_Line1, 
                Delivery_Address_Line2, 'Open', total_amount, gst_value, overall_total_amount, Currency, exchange_rate, gst,swift ,brnach, Terms, 
                  B_client, D_client,Status,overall_total_amount,gst_percent,comments,prj_id))

            db.commit()

            for i in range(len(descriptions)):
                if descriptions[i] and qtys[i] and unit_prices[i]:
                    qty = float(qtys[i])  # Ensure it's a number
                    unit_price = float(unit_prices[i])  # Ensure it's a number
                    total = qty * unit_price  # Compute total

                    cursor.execute("""
                        INSERT INTO invoice_items (inv_no, po_number, prj_id, item, quantity, Unit_Price, total) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (Invoice_No, po_number, prj_id, descriptions[i], qty, unit_price, total))

            db.commit()

            return redirect(url_for("invoice"))
        
    cursor = db.execute('SELECT * FROM created_invoice ORDER BY id DESC')
    created_inv = cursor.fetchall()
    rows = []

    for inv in created_inv:
        id  = inv[0]
        inv_no  = inv[1]
        inv_date  = inv[2]
        po_number  = inv[3]
        prj_id = inv[4]
        attn  = inv[5]
        payment_terms  = inv[6]
        bank_name  = inv[7]
        bank_acc_no = inv[8]
        created_by  = inv[9]
        created_date  = inv[10]
        bill_to_line1  = inv[11]
        bill_to_line2  = inv[12]
        bill_to_line3  = inv[13]
        delivary_to_line1  = inv[14]
        delivary_to_line2  = inv[15]
        delivary_to_line3  = inv[16]
        status  = inv[17]

        gst = inv[23]
        swift = inv[24]
        brnach  = inv[25]
        Terms = inv[26]
        B_client = inv[27]  # Added based on table schema
        D_client = inv[28]  # Added based on table schema

        amount = float(inv[18]) if inv[18] is not None else 0.0
        gst_value = float(inv[19]) if inv[19] is not None else 0.0
        total = float(inv[20]) if inv[20] is not None else 0.0
        Currency = inv[21]
        exchange_rate = float(inv[22]) if inv[22] not in (None, 0, '0', '') else 1.0

        # Apply exchange rate conversion
        amount *= exchange_rate
        gst_value *= exchange_rate
        total *= exchange_rate

        # Handle balance
        balence = float(inv[29]) if inv[29] is not None else 0.0


        Recent_rec_On = inv[30]  # Recent_rec_On is at index 30
        from datetime import datetime, timedelta

        if inv_date:

            try:
                invoice_date = datetime.strptime(inv_date, "%Y-%m-%d")
                today = datetime.today().date()  # Get current date without time

                # Calculate due_date normally based on invoice_date and Terms
                if payment_terms in ['Days', 'Advance']:
                    try:
                        terms_int = int(Terms)  # Ensure Terms is an integer
                        due_date = invoice_date + timedelta(days=terms_int)  # Calculate due date
                    except ValueError:
                        due_date = None
                        print("Invalid value for 'Terms', expected an integer.")
                elif payment_terms == 'COD':  # Payment is due immediately
                    due_date = invoice_date
                else:
                    due_date = None

                # If status is 'Paid', due_days is the difference between due_date and Recent_rec_On
                if status == 'Paid' and Recent_rec_On:
                    try:
                        recent_rec_date = datetime.strptime(Recent_rec_On, "%Y-%m-%d").date()
                        due_days = (due_date.date() - recent_rec_date).days if due_date else None
                    except ValueError:
                        print("Invalid Recent_rec_On format, expected YYYY-MM-DD.")
                        due_days = None
                else:
                    # Calculate due_days as the difference between due_date and today (default behavior)
                    due_days = (due_date.date() - today).days if due_date else None

                due_date_str = due_date.strftime("%m/%d/%y") if due_date else '0/0/0'

            except ValueError:
                print("Invalid Invoice_date format, expected YYYY-MM-DD.")
                due_date = None
                due_days = None
                due_date_str = '0/0/0'

        else:
            due_date = None
            due_days = None
            due_date_str = '0/0/0'


        rows.append({'id': id,'inv_no': inv_no, 'inv_date': inv_date, 'po_number': po_number, 'prj_id': prj_id,'attn': attn, 'payment_terms': payment_terms, 'Currency':Currency,
                     'bank_name': bank_name,'bank_acc_no': bank_acc_no,'created_by': created_by,"created_date":created_date ,"bill_to_line1": bill_to_line1, "Terms":Terms,
                     "delivary_to_line1": delivary_to_line1,"status":status ,"amount":amount ,"gst_value":gst_value ,"total": total, "due_date":due_date_str,
                     "due_days":due_days,"balence":balence,"Recent_rec_On":Recent_rec_On, "B_client":B_client})

    grouped_df_inv = pd.DataFrame(rows)
    grouped_df_inv['inv_date'] = pd.to_datetime(grouped_df_inv['inv_date'], format='%Y-%m-%d', errors='coerce')

    def get_quarter_with_year(date):
        if pd.notna(date):  # Ensure the date is valid
            quarter = (date.month - 1) // 3 + 1  # Determine quarter
            return f'{date.year}-Q{quarter}'  # Format as 'Qx-YYYY'
        return None  # Handle missing dates

    grouped_df_inv['quarter'] = grouped_df_inv['inv_date'].apply(get_quarter_with_year)
    cursor.execute("SELECT Bank_Name FROM bank_details ORDER BY id DESC")
    bank_details = cursor.fetchall()
    return render_template('admin_templates/accounts/invoice.html',user_access=user_access, user=user,bank_details=bank_details,
                          grouped_df_inv=grouped_df_inv, prj_po_list=prj_po_list,department_code=department_code,clients=clients)

@app.route('/get_bank_details', methods=['GET'])
def get_bank_details_route():
    bank_name = request.args.get('bank_name')
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM bank_details WHERE Bank_Name = ?", (bank_name,))
    bank_details = cursor.fetchone()
    
    if bank_details:
        # Print the bank details to the terminal
        print(f"Bank details for {bank_name}:")
        print(f"Account Number: {bank_details[1]}")
        print(f"Branch: {bank_details[2]}")
        print(f"SWIFT: {bank_details[3]}")
        print(f"Pay Now: {bank_details[4]}")
        
        return jsonify({
            'account_number': bank_details[1],
            'branch': bank_details[2],
            'swift': bank_details[3],
            'pay_now': bank_details[4]
        })
    else:
        print(f"No details found for bank: {bank_name}")
        return jsonify({})

@app.route('/ac_get_invoice_details')
def ac_get_invoice_details():
    id = request.args.get('id')
    db = get_database()
    cursor = db.cursor()
    invoice_data = cursor.execute("SELECT * FROM created_invoice WHERE id = ?", (id,)).fetchone()
    cursor.execute("SELECT inv_no FROM created_invoice WHERE id = ?", (id,)) 
    result = cursor.fetchone()  
    inv_no = result[0]
    items = cursor.execute("SELECT * FROM invoice_items WHERE inv_no = ?", (inv_no,)).fetchall()
    history_items = cursor.execute("SELECT * FROM invoice_pay_history WHERE inv_no = ?", (inv_no,)).fetchall()
    if not invoice_data:
        return jsonify({'success': False, 'message': 'Payment request not found'})
    return jsonify({
        'success': True,
        'invoice_data': dict(invoice_data),
        'items': [dict(item) for item in items],
        'history_items': [dict(history_item) for history_item in history_items],
    })

@app.route("/invoice_prj_details", methods=["POST"])
def invoice_prj_details():
    data = request.json
    projectid = data.get("projectid")
    db = get_database()
    cursor = db.cursor()
    query = '''SELECT client, delivery_address, delivery_address2, delivery_address3, billing_address, billing_address2, billing_address3
               FROM projects WHERE id = ?'''
    cursor.execute(query, (projectid,))
    result = cursor.fetchone()
    if result:
        client, delivery_address, delivery_address2, delivery_address3, billing_address, billing_address2, billing_address3 = result
        print("....delivery_address, delivery_address2, delivery_address3, billing_address, billing_address2, billing_address3................",delivery_address, delivery_address2, delivery_address3, billing_address, billing_address2, billing_address3)
        return jsonify({
            "client" : client,
            "delivery_address" : delivery_address,
            "delivery_address2" : delivery_address2,
            "delivery_address3" : delivery_address3,
            "billing_address" : billing_address,
            "billing_address2" : billing_address2,
            "billing_address3" : billing_address3
        })
    
    return jsonify({"error": "Client not found"}), 404

@app.route("/get_client_details", methods=["POST"])
def get_client_details():
    data = request.json
    selected_client = data.get("client")
    db = get_database()
    cursor = db.cursor()
    query = '''SELECT billing_address1, billing_address2, billing_city, billing_postcode, billing_country, company_name 
               FROM client_details WHERE display_name = ?'''
    cursor.execute(query, (selected_client,))
    result = cursor.fetchone()
    if result:
        billing_address1, billing_address2, city, postcode, country, company_name = result
        billing_address2_formatted = f"{country}, {city} - {postcode}"
        return jsonify({
            "billing_address1": billing_address1,
            "billing_address2": billing_address2_formatted,
            "company_name": company_name
        })
    
    return jsonify({"error": "Client not found"}), 404

@app.route("/get_client_delivary_details", methods=["POST"])
def get_client_delivary_details():
    data = request.json
    selected_client = data.get("client")
    db = get_database()
    cursor = db.cursor()

    query = '''SELECT delivery_address1, delivery_address2, delivery_city, delivery_postcode, delivery_country, company_name 
               FROM client_details WHERE display_name = ?'''
    cursor.execute(query, (selected_client,))
    result = cursor.fetchone()
    if result:
        billing_address1, billing_address2, city, postcode, country, company_name = result
        billing_address2_formatted = f"{country}, {city} - {postcode}"
        return jsonify({
            "billing_address1": billing_address1,
            "billing_address2": billing_address2_formatted,
            "company_name": company_name
        })
    
    return jsonify({"error": "Client not found"}), 404

from flask import jsonify
@app.route('/get_gst_for_year/<int:year>', methods=['GET'])
def get_gst_for_year(year):
    db = get_database()
    cursor = db.cursor()
    query = """ SELECT GST  FROM GST  WHERE strftime('%Y', Date) = ? ORDER BY Date DESC LIMIT 1"""
    cursor.execute(query, (str(year),))
    result = cursor.fetchone()
    gst_value = result[0] if result else 1  # Default to 1 if no result
    return jsonify({"gst_value": gst_value})

@app.route('/delete_invoice', methods=['POST'])
def delete_invoice():
    db = get_database()
    cursor = db.cursor()
    data = request.get_json()
    invoice_id = data.get('invoiceId')
    cursor.execute("SELECT inv_no FROM created_invoice WHERE id = ?", (invoice_id,))
    invoice = cursor.fetchone()
    if invoice:
        inv_no = invoice['inv_no']
        cursor.execute("DELETE FROM invoice_items WHERE inv_no = ?", (inv_no,))
        cursor.execute("DELETE FROM created_invoice WHERE id = ?", (invoice_id,))
        db.commit()
        return jsonify({"status": "success", "message": "Invoice and related items deleted successfully."}), 200
    else:
        return jsonify({"status": "error", "message": "Invoice not found."}), 404

from flask import jsonify, request
@app.route('/get_invoice_details/<invoice_no>', methods=['GET'])
def get_invoice_details(invoice_no):
    db = get_database()
    cursor = db.cursor()
    
    # Fetching invoice details
    cursor.execute("SELECT * FROM created_invoice WHERE inv_no = ?", (invoice_no,))
    invoice = cursor.fetchone()
    print(len(invoice))  # To see the number of columns fetched

    
    # Fetching associated invoice items
    cursor.execute("SELECT * FROM invoice_items WHERE inv_no = ?", (invoice_no,))
    items = cursor.fetchall()
    
    if invoice:
        # Return the data as JSON, with all fields from `created_invoice`
        return jsonify({
            'inv_no': invoice[1],
            'inv_date': invoice[2],
            'po_number': invoice[3],
            'prj_id': invoice[4],
            'attn': invoice[5],
            'payment_terms': invoice[6],
            'bank_name': invoice[7],
            'bank_acc_no': invoice[8],
            'created_by': invoice[9],
            'created_date': invoice[10],
            'bill_to_line1': invoice[11],
            'bill_to_line2': invoice[12],
            'bill_to_line3': invoice[13],
            'delivary_to_line1': invoice[14],
            'delivary_to_line2': invoice[15],
            'delivary_to_line3': invoice[16],
            'status': invoice[17],
            'amount': invoice[18],
            'gst_value': invoice[19],
            'total': invoice[20],
            'currency': invoice[21],
            'exchange_rate': invoice[22],
            'gst': invoice[23],
            'swift': invoice[24],
            'branch': invoice[25],
            'terms': invoice[26],
            'B_client': invoice[27],
            'D_client': invoice[28],
            'comments': invoice[33],
            'items': [{'item': item[4], 'quantity': item[5], 'unit_price': item[6], 'total': item[7]} for item in items]
        })
    else:
        return jsonify({'error': 'Invoice not found'}), 404

@app.route('/add_expense', methods=["POST", "GET"])
@login_required
def add_expense():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    query = """SELECT * FROM claims WHERE claim_id LIKE 'E%' ORDER BY id DESC;"""
    cursor.execute(query)
    claims_data = cursor.fetchall()
    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    cursor.execute("SELECT type, type_values FROM expenses_values")
    rows = cursor.fetchall()

    cursor.execute("SELECT Building_Name FROM Accommodation")
    accommodation_names = [row['Building_Name'] for row in cursor.fetchall()]

    cursor.execute("SELECT Vehicle_number FROM vehicle")
    vehicle_names = [row['Vehicle_number'] for row in cursor.fetchall()]

    # Construct unified structure
    expense_types = []
    for row in rows:
        type_name = row["type"]
        type_values = row["type_values"]
         
        if type_name == "Housing":
            parents = accommodation_names
        elif type_name == "Utilities":
            parents = accommodation_names
        elif type_name == "Vehicle":
            parents = vehicle_names
        else:
            parents = []  # No parent level for other types

        expense_types.append({
            "type": type_name,
            "parents": parents,
            "children": [val.strip() for val in type_values.split(",") if val.strip()]
        })
    print("...expense_types...........",expense_types)


    return render_template('admin_templates/accounts/add_expense.html',user_access=user_access, gst=gst,
                             user=user,department_code=department_code,claims_data=claims_data,expense_types=expense_types)

@app.route('/ac_submit_expenses', methods=['POST'])
def ac_submit_expenses():
    data = request.get_json()
    user = get_current_user()
    from datetime import datetime

    try:
        expenses = data.get('expenses', [])
        comments = data.get('comments', '')
        totals = data.get('totals', {})

        # Connect to your SQLite database
        db = get_database()
        cursor = db.cursor()
        # Generate a new claim ID
        current_year = datetime.now().year
        cursor.execute('SELECT id FROM claims ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        last_claim_no = result[0] if result else 0
        formatted_claim_no = f"{last_claim_no + 1:04d}"
        latest_claim_no = f"E-{str(current_year)[-2:]}-{formatted_claim_no}"

        # Insert into claims table
        claim_date = datetime.now().date()
        cursor.execute('''
            INSERT INTO claims ( claim_id, claim_by, claim_date, comments, status, claim_Total, claim_type, amount, gst_value) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (latest_claim_no,user['name'], claim_date, comments,'Paid',float(totals.get('grand', 0)),'expense', 
              float(totals.get('amount', 0)), float(totals.get('gst', 0))))

        # Insert each expense item into claimed_items table
        for exp in expenses:
            cursor.execute('''
                INSERT INTO claimed_items (
                    claim_by, date, Category,
                    Sub_Category, vendor, itemname, Currency, comments,
                    Rate, invoice_number, amount, gst_value,
                    total, claim_no, claim_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user['name'],exp.get('date'), exp.get('expenses'), exp.get('category'), exp.get('vendor'), exp.get('description'), 'SGD',                  
                comments,1, exp.get('invoice'),float(exp.get('amount', 0)),float(exp.get('gst', 0)),   
                            float(exp.get('total', 0)),latest_claim_no,'Expense'    
            ))

            db.execute(""" INSERT INTO manual_entry (username, project_id, cost, gst_value, total, cost_center_id, department_code)
                    VALUES (?, ?, ?, ?, ?, ?, ?) """, ( user['name'], 1, float(exp.get('amount', 0)), 
                                                       float(exp.get('gst', 0)), float(exp.get('total', 0)), latest_claim_no,0 ))

        db.commit()
     

        return jsonify({'status': 'success', 'claim_id': latest_claim_no})

    except Exception as e:
        return jsonify({'status': 'fail', 'message': str(e)}), 500

@app.route('/ac_pay_req', methods=["POST", "GET"])
@login_required
def ac_pay_req():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    visibility = 'approve_claims'
    cursor = db.execute('SELECT * FROM payment_request ORDER BY Invoice_date DESC')
    payment_request = cursor.fetchall()
    rows = []
    vendor_query = "SELECT company_name FROM vendors_details WHERE display_name = ?"
    cursor = db.execute("SELECT claim_id, status, approved_date FROM claims")
    claims_data = cursor.fetchall()
    claims_dict = {claim["claim_id"]: {"status": 'Paid' if claim["status"] == 'Paid' else 'Pending', "approved_date": claim["approved_date"],"items": []}
                   for claim in claims_data}

    for pay in payment_request:
        pay_number = pay[1]
        status = pay[6]
        amount = pay[10]
        invoice_file_name = pay[11]
        paid_date = pay[12]
        overall_total_amount = pay[14]
        Invoice_date = pay[15]
        gst_stat = pay[16]
        gst_value = pay[17]
        supplier_name = pay[18]
        Exchange_rate = pay[26] if len(pay) > 26 and pay[26] not in (None, '', 0) else 1
        # Fetch supplier name once per payment request
        cursor.execute(vendor_query, (supplier_name,))
        result = cursor.fetchone()
        supplier_full_name = result[0] if result else supplier_name

        Terms = pay[20]
        time_period = pay[21]

        # Handle time_period-based logic
        from datetime import datetime, timedelta
        if time_period in ['Days', 'Advance']:
            try:
                invoice_date = datetime.strptime(Invoice_date, "%Y-%m-%d")
                due_date = invoice_date + timedelta(days=int(Terms))
                due_days = (due_date - datetime.today()).days
            except ValueError:
                due_date = due_days = None
        elif time_period == 'COD':
            try:
                invoice_date = datetime.strptime(Invoice_date, "%Y-%m-%d")
                due_date = invoice_date
                due_days = 1
            except ValueError:
                due_date = None
                due_days = None
        else:
            due_date = due_days = None

        due_date_str = due_date.strftime("%m/%d/%y") if due_date else 'None'
        from datetime import datetime

        # Append payment request data to rows
        rows.append({
            'expences_id': pay_number,
            'Invoice_date': Invoice_date,
            'supplier_name': supplier_full_name,
            'amount': amount * Exchange_rate,
            'gst_value': gst_value * Exchange_rate,
            'overall_total_amount': overall_total_amount * Exchange_rate,
            'Terms': Terms,
            'due_date': due_date_str,
            'status': status,
            'paid_date': paid_date,
            'due_days': due_days,
            'invoice_file_name': invoice_file_name,
            'time_period': time_period
        })

    for claim_id, data in claims_dict.items():
        # print("..........data.............",data)
        cursor.execute( "SELECT claim_no, date, vendor, amount, gst_value, total, Rate,Sub_Category,itemname FROM claimed_items WHERE claim_no = ? ORDER BY date DESC", (claim_id,) )
        items = [dict(row) for row in cursor.fetchall()]
        for item in items:
            Exchange_rate = item.pop("Rate", 1)


            item["expences_id"] = item.pop("claim_no", None)
            item["Invoice_date"] = item.pop("date", None)
            item["supplier_name"] = item.pop("vendor", None)
            item["Sub_Category"] = item.pop("Sub_Category", None)
            item["itemname"] = item.pop("itemname", None)

            try:
                amount_str = item.pop("amount", None)
                item["amount"] = float(amount_str) * Exchange_rate if amount_str is not None else 0
            except (ValueError, TypeError):
                item["amount"] = 0

            try:
                gst_value_str = item.pop("gst_value", None)
                item["gst_value"] = float(gst_value_str) * Exchange_rate if gst_value_str is not None else 0
            except (ValueError, TypeError):
                item["gst_value"] = 0

            try:
                total_str = item.pop("total", None)
                item["overall_total_amount"] = float(total_str) * Exchange_rate if total_str is not None else 0
            except (ValueError, TypeError):
                item["overall_total_amount"] = 0


 

            item["status"] = data["status"]
            item["paid_date"] = data.get("approved_date", None) 
            item["due_days"] = item.pop('due_days', None)
            item["invoice_file_name"] = item.pop('invoice_file_name', None)
            item["time_period"] = item.pop('time_period', None)

        claims_dict[claim_id]["items"] = items
        rows.extend(items)

    grouped_df = pd.DataFrame(rows)
    grouped_df['Invoice_date'] = pd.to_datetime(grouped_df['Invoice_date'], errors='coerce')
    grouped_df = grouped_df.sort_values(by='Invoice_date', ascending=False)
    grouped_df['Invoice_date'] = grouped_df['Invoice_date'].dt.strftime('%d/%m/%y')

    date_columns = [ 'paid_date', 'due_date']
    
    for col in date_columns:
        grouped_df[col] = pd.to_datetime(grouped_df[col], errors='coerce')

    for col in date_columns:
        grouped_df[col] = grouped_df[col].dt.strftime('%d/%m/%y').fillna('')

    grouped_df['Invoice_date'] = pd.to_datetime(grouped_df['Invoice_date'], format='%d/%m/%y', errors='coerce')

    def get_quarter_with_year(date):
        if pd.notna(date):  # Ensure the date is valid
            quarter = (date.month - 1) // 3 + 1  # Determine quarter
            return f'{date.year}-Q{quarter}'  # Format as 'Qx-YYYY'
        return None  # Handle missing dates

    grouped_df['quarter'] = grouped_df['Invoice_date'].apply(get_quarter_with_year)
    grouped_df['Invoice_date'] = grouped_df['Invoice_date'].dt.strftime('%d/%m/%y')


    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/accounts/ac_pay_req.html',  user_access=user_access, grouped_df=grouped_df,visibility=visibility, user=user, department_code=department_code,)

@app.route('/reports', methods=["POST", "GET"])
@login_required
def reports():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    query = """SELECT * FROM claims WHERE claim_by = ? AND claim_id LIKE 'E%' ORDER BY id DESC;"""
    params = (user['name'],)
    cursor.execute(query, params)
    claims_data = cursor.fetchall()
    cursor.execute('SELECT display_name FROM client_details')
    Cilents = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT Vehicle_number, Vehicle_name FROM vehicle')
    vehicles = cursor.fetchall()
    Vehicle_numbers = [{'number': row[0], 'name': row[1]} for row in vehicles]
    return render_template('admin_templates/accounts/reports.html',user_access=user_access, user=user,department_code=department_code,
                           Vehicle_numbers=Vehicle_numbers,claims_data=claims_data, Cilents=Cilents)

@app.route("/generate_GST_report", methods=["POST"])
def generate_GST_report():
    db = get_database()
    cursor = db.cursor()
    data = request.get_json()

    quarter = data.get("quarter")
    start_date = data.get("start_date")
    end_date = data.get("end_date")
    format = data.get("format")
    from datetime import datetime


    # Determine date range
    if quarter:
        year = datetime.today().year
        quarter_mapping = {"Q1": (1, 3), "Q2": (4, 6), "Q3": (7, 9), "Q4": (10, 12)}
        start_month, end_month = quarter_mapping[quarter]
        start = datetime(year, start_month, 1)
        end = datetime(year, end_month, 1).replace(day=28) + pd.offsets.MonthEnd(0)
        if isinstance(end, pd.Timestamp):
            end = end.to_pydatetime()
        start = start.strftime('%Y-%m-%d')
        end = end.strftime('%Y-%m-%d')
    
    else:
        start = start_date
        end = end_date

    # Fetch payment requests (GST > 0 only)
    payment_query = '''
        SELECT 
            pr.pay_number AS reference_no,
            pr.Invoice_date AS date,
            pr.invoice_no AS invoice_number,
            vd.company_name AS company_name,
            pr.supplier_name AS display_name,
            pr.amount * pr.Exchange_rate AS amount,  
            pr.gst_value AS gst_value,
            pr.overall_total_amount AS total,
            'Payment' AS source
        FROM payment_request pr
        LEFT JOIN vendors_details vd ON pr.supplier_name = vd.display_name
        WHERE DATE(pr.Invoice_date) BETWEEN DATE(?) AND DATE(?)
        AND pr.gst_value > 0
        ORDER BY pr.Invoice_date DESC
    '''

    
    cursor = db.execute(payment_query, (start, end))
    pay_rows = cursor.fetchall()

    # Fetch claims (GST > 0 only)
    claim_query = ''' 
        SELECT claim_no AS reference_no, date, invoice_number, vendor AS display_name,
            amount, gst_value, total, 'Claim' AS source
        FROM claimed_items 
        WHERE DATE(date) BETWEEN DATE(?) AND DATE(?) 
        AND gst_value > 0
        ORDER BY date DESC 
    '''
    cursor = db.execute(claim_query, (start, end))
    claim_rows = cursor.fetchall()

    # Merge payments & claims
    merged_records = []
    for row in pay_rows:
        formatted_date = datetime.strptime(row["date"], "%Y-%m-%d").strftime("%d-%m-%y")
        merged_records.append({
            "Date": formatted_date,
            "Source": row["source"],
            "Reference No": row["reference_no"],
            "Description": row["invoice_number"],
            "GST Code": "SR-09",
            "GST %": "9.00%",
            "Amount": row["amount"],
            "GST Value": row["gst_value"],
            "Total": row["total"]
        })
    
    for row in claim_rows:
        formatted_date = datetime.strptime(row["date"], "%Y-%m-%d").strftime("%d-%m-%y")
        merged_records.append({
            "Date": formatted_date,
            "Source": row["source"],
            "Reference No": row["reference_no"],
            "Description": row["invoice_number"],
            "Name": row["display_name"],
            "GST Code": "TX-09",
            "GST %": "9.00%",
            "Amount": row["amount"],
            "GST Value": row["gst_value"],
            "Total": row["total"]
        })

    # Fetch invoices (both GST and zero rated)
    invoice_query = ''' 
        SELECT inv_no AS reference_no, inv_date AS date, bill_to_line1 AS name,
               amount, gst_value, total
        FROM created_invoice 
        WHERE DATE(inv_date) BETWEEN DATE(?) AND DATE(?) 
        ORDER BY inv_date DESC 
    '''
    cursor = db.execute(invoice_query, (start, end))
    inv_rows = cursor.fetchall()

    invoices_with_gst = []
    invoices_zero_rated = []

    for row in inv_rows:
        formatted_date = datetime.strptime(row["date"], "%Y-%m-%d").strftime("%d-%m-%y")
        invoice = {
            "Date": formatted_date,
            "Source": "Invoice",
            "Reference No": row["reference_no"],
            "Description": "",
            "Name": row["name"],
            "GST Code": "SR-09" if row["gst_value"] > 0 else "ZR",
            "GST %": "9.00%" if row["gst_value"] > 0 else "0.00%",
            "Amount": row["amount"],
            "GST Value": row["gst_value"],
            "Total": row["total"]
        }
        if row["gst_value"] > 0:
            invoices_with_gst.append(invoice)
        else:
            invoices_zero_rated.append(invoice)

    # Create DataFrames
    df_merged = pd.DataFrame(merged_records)
    df_invoices_with_gst = pd.DataFrame(invoices_with_gst)
    df_invoices_zero_rated = pd.DataFrame(invoices_zero_rated)

    # Function to append total row
    def append_total_row(df):
        total_row = {col: "" for col in df.columns}
        total_row["Source"] = "TOTAL"
        if "Amount" in df.columns:
            total_row["Amount"] = df["Amount"].sum()
        if "GST Value" in df.columns:
            total_row["GST Value"] = df["GST Value"].sum()
        if "Total" in df.columns:
            total_row["Total"] = df["Total"].sum()
        return pd.concat([df, pd.DataFrame([total_row])], ignore_index=True)

    # Append totals to all dfs
    df_merged = append_total_row(df_merged)
    df_invoices_with_gst = append_total_row(df_invoices_with_gst)
    df_invoices_zero_rated = append_total_row(df_invoices_zero_rated)

    # Assuming the columns are named exactly "Amount" and "GST Value"
    total_df_merged_amount = df_merged['Amount'].sum()
    total_df_merged_gst = df_merged['GST Value'].sum()

    total_df_gst_amount = df_invoices_with_gst['Amount'].sum()
    total_df_gst_gst = df_invoices_with_gst['GST Value'].sum()

    total_df_zero_amount = df_invoices_zero_rated['Amount'].sum()
    total_df_zero_gst = df_invoices_zero_rated['GST Value'].sum()


    # Export to Excel
    if format == "xlsx":
        output = BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')
        df_merged.to_excel(writer, index=False, sheet_name="Payments_Claims")
        df_invoices_with_gst.to_excel(writer, index=False, sheet_name="Invoices_With_GST")
        df_invoices_zero_rated.to_excel(writer, index=False, sheet_name="Sales_Zero_Rated")
        writer.close()
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name="Finance_Report.xlsx",
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )

    # Export to PDF
    elif format == "pdf":
        
        def create_pdf_sections(sections, start_date, end_date, total_df_merged_amount, total_df_merged_gst, 
                                total_df_gst_amount, total_df_gst_gst, total_df_zero_amount, total_df_zero_gst ):

            def format_date(date_str):
                try:
                    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d-%m-%y")
                except:
                    return date_str

            start_date_fmt = format_date(start_date)
            end_date_fmt = format_date(end_date)

            pdf = FPDF(orientation='L', unit='mm', format='A4')
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            # Main page box
            left_margin = 7
            top_margin = 7
            box_width = 283
            box_height = 180
            pdf.set_draw_color(0, 0, 0)
            pdf.rect(left_margin, top_margin, box_width, box_height)

            # Title and Subheading box
            pdf.set_fill_color(220, 230, 250)  # Light blue background
            pdf.set_text_color(0, 51, 102)     # Dark blue text
            pdf.set_draw_color(0, 51, 102)     # Border color

            # Draw a filled rectangle for the title area
            pdf.rect(left_margin + 10, top_margin + 10, box_width - 20, 20, style='DF')

            # Set font for the title
            pdf.set_font("Arial", 'B', 16)
            pdf.set_xy(left_margin + 10, top_margin + 13)
            pdf.cell(box_width - 20, 10, "CENTROID ENGINEERING SOLUTIONS PTE LTD", ln=True, align='C')

            # Subheading (date range)
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(0, 0, 0)  # Reset to black for subheading
            pdf.set_x(left_margin + 10)
            pdf.cell(box_width - 20, 10, f"Accounting period covered by this return  {start_date_fmt}  TO  {end_date_fmt}", ln=True, align='C')

            summary_data = [
                ("Total value of standard-rated supplies", f"{total_df_gst_amount:,.2f}"),
                ("Total value of zero rated-supplies", f"{total_df_zero_amount:,.2f}"),
                ("Total value of exempt supplies", "-"),
                ("Total value of (1) + (2) + (3)", f"{(total_df_gst_amount + total_df_zero_amount):,.2f}"),
                ("Total value of taxable purchases", f"{total_df_merged_amount:,.2f}"),
                ("Output tax due", f"{total_df_gst_gst:,.2f}"),
                ("Less :", ""),
                ("Input tax and refunds claimed", f"{total_df_merged_gst:,.2f}"),
                ("Equals", ""),
                ("Net GST to be paid to IRAS", f"{(total_df_gst_gst - total_df_merged_gst):,.2f}"),
                ("Net GST to be claimed from IRAS", ""),
                ("APPLICABLE TO TAXABLE PERSONS UNDER MAJOR EXPORTER SCHEME", ""),
                ("Total value of goods imported under this scheme", "-"),
            ]

    
            left_margin = 50
            right_margin = 20
            page_width = 250  # A4 width in mm
            usable_width = page_width - left_margin - right_margin

            pdf.set_font("Arial", 'B', 11)
            pdf.set_xy(left_margin, top_margin + 40)

            label_width = usable_width * 0.65  # 65% of space for label
            value_width = usable_width * 0.35  # 35% of space for value

            for label, value in summary_data:
                pdf.set_x(left_margin)  # Ensure each line starts at the left margin
                if value:
                    pdf.cell(label_width, 8, label, border=0)
                    pdf.cell(value_width, 8, value, border=0, ln=True, align='R')
                else:
                    pdf.cell(0, 8, label, ln=True)


            # New page for data sections
            pdf.add_page()
            pdf.set_font("Arial", size=9)
            line_height = 6

            def draw_table_header(cols, col_widths):
                pdf.set_font("Arial", 'B', 9)
                for i, col in enumerate(cols):
                    pdf.cell(col_widths[i], line_height, str(col)[:15], border=1, align='C')
                pdf.ln(line_height)
                pdf.set_font("Arial", size=9)

            for section_title, df in sections:
                # Force a new page before df_invoices_with_gst section
                if section_title == "Sales-Output":
                    pdf.add_page()

                pdf.set_font("Arial", 'B', 10)
                pdf.cell(0, 10, section_title, ln=True, align='L')
                pdf.set_font("Arial", size=9)

                cols = ["S/N"] + list(df.columns)

                width_map = {
                    "S/N": 10,
                    "Date": 17,
                    "Source": 17,
                    "Reference No": 24,
                    "Description": 55,
                    "Name": 55,
                    "GST Code": 18,
                    "GST %": 15,
                    "Amount": 20,
                    "GST Value": 20,
                    "Total": 25,
                }

                right_align_cols = {"Amount", "GST Value", "Total"}
                col_widths = [width_map.get(col, 40) for col in cols]

                draw_table_header(cols, col_widths)

                serial_number = 1
                for _, row in df.iterrows():
                    if pdf.get_y() > 190:
                        pdf.add_page()
                        draw_table_header(cols, col_widths)

                    is_total_row = any(str(row[col]).strip().lower() == "total" for col in df.columns)

                    if not is_total_row:
                        pdf.cell(col_widths[0], line_height, str(serial_number), border=1, align='C')
                        serial_number += 1
                    else:
                        pdf.cell(col_widths[0], line_height, "", border=1)

                    for i, col in enumerate(df.columns, 1):
                        value = row[col]
                        if pd.isnull(value):
                            value_str = ''
                        elif col in right_align_cols and isinstance(value, (int, float)):
                            value_str = f"{value:,.2f}"
                        else:
                            value_str = str(value)

                        if col in ["Description", "Name"]:
                            value_str = value_str[:25]

                        align = 'R' if col in right_align_cols else 'L'
                        pdf.cell(col_widths[i], line_height, value_str[:30], border=1, align=align)
                    pdf.ln(line_height)
                pdf.ln(10)

            output = BytesIO()
            pdf_bytes = pdf.output(dest='S').encode('latin-1')
            output.write(pdf_bytes)
            output.seek(0)
            return output

        start1 = datetime.strptime(start, "%Y-%m-%d")
        end1 = datetime.strptime(end, "%Y-%m-%d")

        # Format to DD-MM-YY
        start_date_fmt = start1.strftime("%d-%m-%y")
        end_date_fmt = end1.strftime("%d-%m-%y")


        sections = [
            (f'Input tax {start_date_fmt} to {end_date_fmt}', df_merged),
            ("Sales-Output", df_invoices_with_gst),
            ("Sales - Zero Rated", df_invoices_zero_rated),
        ]

        pdf_output = create_pdf_sections(sections,start,end,total_df_merged_amount, total_df_merged_gst, 
                                         total_df_gst_amount, total_df_gst_gst, total_df_zero_amount, total_df_zero_gst )

        return send_file(
            pdf_output,
            as_attachment=True,
            download_name="Finance_Report.pdf",
            mimetype='application/pdf'
        )

    else:
        return {"error": "Unsupported format"}, 400

from flask import send_file, request, jsonify
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

from io import BytesIO
import sqlite3

@app.route("/generate_SOA_report", methods=["POST"])
def generate_SOA_report():
    data = request.get_json()
    SOAClient = data.get("SOAClient")
    SOAdate = data.get("SOAdate")
    from datetime import datetime, timedelta

    SOAdate_obj = datetime.strptime(SOAdate, "%Y-%m-%d")
    report_date = SOAdate_obj.strftime("%d-%m-%y")

    db = get_database()
    cursor = db.cursor()
    cursor.execute(""" SELECT inv_no, po_number, inv_date, Currency, total, Terms, status FROM created_invoice 
        WHERE bill_to_line1 = ? AND status != 'Paid' AND DATE(inv_date) <= DATE(?) ORDER BY inv_date """, (SOAClient, SOAdate))
    invoices = cursor.fetchall()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Logo
    logo_path = "static/CENTROID Logo.jpg"
    pdf.drawImage(logo_path, 30, height - 90, width=130, preserveAspectRatio=True)

    # Company Info
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(35, height - 80, "Centroid Engineering Solutions Pte Ltd")
    pdf.setFont("Helvetica", 9)
    pdf.drawString(35, height - 95, "Co Regn / GST No: 201308058R")
    pdf.drawString(35, height - 110, "11, Woodlands Close, #07-10")
    pdf.drawString(35, height - 125, "Singapore - 737853")

    # Title & Date
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawCentredString(width / 2, height - 150, "STATEMENT")
    pdf.setFont("Helvetica", 9)
    pdf.drawRightString(width - 40, height - 170, f"Date: {report_date}")
    pdf.drawString(35, height - 170, "Open Item List")

    # =========================
    # Table 1: Invoice Details
    # =========================

    table_data = [["Inv. Number", "Cust PO Number", "Inv Date", "Curr", "Amount", "Net Due Date", "Days"]]
    today = datetime.strptime(SOAdate, "%Y-%m-%d")

    aging_buckets = {
        "0 - 60 Days": 0,
        "61 - 90 Days": 0,
        "91 - 120 Days": 0,
        "121 - 150 Days": 0,
        "Over 150 Days": 0
    }

    total_amount = 0

    for inv in invoices:

        try:
            inv_no, po_number, inv_date, curr, amount, terms, status = inv
            inv_date_obj = datetime.strptime(inv_date, "%Y-%m-%d")
            net_due_date = inv_date_obj + timedelta(days=int(terms) if terms else 0)

            amount_val = float(amount)
            total_amount += amount_val

            days_diff = (net_due_date - today).days

            # Clear text for days due/overdue
            if days_diff < 0:
                days_str = f"Overdue {abs(days_diff)}d"
            else:
                days_str = f"Due {days_diff}d"


            # Categorize into aging buckets
            amount_val = float(amount)


            if days_diff <= 60:
                aging_buckets["0 - 60 Days"] += amount_val
            elif 61 <= days_diff <= 90:
                aging_buckets["61 - 90 Days"] += amount_val
            elif 91 <= days_diff <= 120:
                aging_buckets["91 - 120 Days"] += amount_val
            elif 121 <= days_diff <= 150:
                aging_buckets["121 - 150 Days"] += amount_val
            else:
                aging_buckets["Over 150 Days"] += amount_val

            # Prepare table row
            formatted_amount = f"{amount_val:,.2f}"
            row = [
                inv_no,
                po_number,
                inv_date_obj.strftime("%d-%m-%y"),
                curr,
                formatted_amount,
                net_due_date.strftime("%d-%m-%y"),
                days_str
            ]
            table_data.append(row)

        except Exception as e:
            print(f"Error processing invoice {inv}: {e}")


    formatted_total = f"{total_amount:,.2f}"
    total_row = ["", "", "", "Total", formatted_total, "", ""]  # Align "Total" under Curr, amount under Amount
    table_data.append(total_row)

    invoice_table = Table(table_data, colWidths=[90, 120, 70, 45, 65, 70, 60])
    invoice_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ALIGN', (4, 1), (4, -1), 'RIGHT'),
        ('ALIGN', (1, 1), (1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
    ]))

    # Calculate position just below the "Open Item List"
    open_item_y = height - 185
    table_width, table_height = invoice_table.wrapOn(pdf, width - 70, open_item_y)
    invoice_table.drawOn(pdf, 35, open_item_y - table_height)

    # =========================
    # Balance Text
    # =========================
    balance_y = open_item_y - table_height - 30
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(35, balance_y, f"Balance as at {report_date}")

    # =========================
    # Table 2: Aging Summary
    # =========================

    aging_row = [
        "Overdue Since", "SGD",
        f"{aging_buckets['0 - 60 Days']:,.2f}",
        f"{aging_buckets['61 - 90 Days']:,.2f}",
        f"{aging_buckets['91 - 120 Days']:,.2f}",
        f"{aging_buckets['121 - 150 Days']:,.2f}",
        f"{aging_buckets['Over 150 Days']:,.2f}"
    ]

    aging_table_data = [
        ["Type", "Curr", "0 - 60 Days", "61 - 90 Days", "91 - 120 Days", "121 - 150 Days", "Over 150 Days"],
        aging_row
    ]


    aging_table = Table(aging_table_data, colWidths=[80, 40, 80, 80, 80, 80, 80])
    aging_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ALIGN', (2, 1), (-1, -1), 'RIGHT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
    ]))

    aging_table_y = balance_y - 30 - 15  # Extra spacing
    aging_table.wrapOn(pdf, width - 70, aging_table_y)
    aging_table.drawOn(pdf, 35, aging_table_y)

    # =========================
    # Overdue Summary
    # =========================
    # overdue_y = aging_table_y - 40
    # pdf.setFont("Helvetica-Bold", 10)
    # pdf.drawString(30, overdue_y, "Overdue Since:")
    # pdf.setFont("Helvetica", 10)
    # pdf.setFillColor(colors.red)
    # pdf.drawString(120, overdue_y, f"SGD {total_overdue:,.2f}")
    # pdf.setFillColor(colors.black)

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return send_file( buffer, as_attachment=True, download_name="SOA_Report.pdf", mimetype='application/pdf')


@app.route('/get_vehicle_expense_summary')
def get_vehicle_expense_summary():
    try:
        db = get_database()
        cursor = db.cursor()
        cursor.execute("""
            SELECT 
                TRIM(SUBSTR(Sub_Category, 1, INSTR(Sub_Category, ' - ') - 1)) AS vehicle_number,
                CASE STRFTIME('%m', date)
                    WHEN '01' THEN 'Jan'
                    WHEN '02' THEN 'Feb'
                    WHEN '03' THEN 'Mar'
                    WHEN '04' THEN 'Apr'
                    WHEN '05' THEN 'May'
                    WHEN '06' THEN 'Jun'
                    WHEN '07' THEN 'Jul'
                    WHEN '08' THEN 'Aug'
                    WHEN '09' THEN 'Sep'
                    WHEN '10' THEN 'Oct'
                    WHEN '11' THEN 'Nov'
                    WHEN '12' THEN 'Dec'
                END AS month_name,
                TRIM(SUBSTR(Sub_Category, INSTR(Sub_Category, ' - ') + 3)) AS type,
                SUM(amount) AS total_amount
            FROM claimed_items
            WHERE claim_type IN ('Expense', 'vehicle')
            AND Category = 'Vehicle'
            AND Sub_Category LIKE '% - %'
            GROUP BY vehicle_number, month_name, type
            ORDER BY vehicle_number, month_name, type;

        """)

        rows = cursor.fetchall()

        # Raw data for backward compatibility
        raw_data = []
        for row in rows:
            raw_data.append({
                'vehicle_number': row[0],
                'month_name': row[1],
                'type': row[2],
                'total_amount': float(row[3])
            })
        print(".............raw_data............",raw_data)
        # Calculate all metrics and chart data
        chart_data = prepare_chart_data(raw_data)
        print(".....chart_data........",chart_data)
        
        return jsonify({
            'success': True, 
            'data': raw_data,  # Keep for backward compatibility
            'chart_data': chart_data
        })
    except Exception as e:
        print("Error:", e)
        return jsonify({'success': False, 'error': str(e)})

def prepare_chart_data(vehicle_data):

    if not vehicle_data:
        return {}
    print(".....vehicle_data........",vehicle_data)
    
    # 1. Calculate basic metrics
    total_expense = sum(item['total_amount'] for item in vehicle_data)
    unique_vehicles = list(set(item['vehicle_number'] for item in vehicle_data))
    unique_months = list(set(item['month_name'] for item in vehicle_data))
    
    # Category totals for highest category
    category_totals = {}
    for item in vehicle_data:
        category_totals[item['type']] = category_totals.get(item['type'], 0) + item['total_amount']
    
    highest_category = max(category_totals.items(), key=lambda x: x[1])
    
    metrics = {
        'total_expense': total_expense,
        'vehicle_count': len(unique_vehicles),
        'monthly_average': total_expense / len(unique_months) if unique_months else 0,
        'highest_category': highest_category[0],
        'highest_category_amount': highest_category[1]
    }
    
    # 2. Total Cost by Vehicle Chart Data
    vehicle_totals = {}
    for item in vehicle_data:
        vehicle_totals[item['vehicle_number']] = vehicle_totals.get(item['vehicle_number'], 0) + item['total_amount']
    
    total_cost_chart = {
        'labels': [],
        'data': [],
        'insights': {}
    }
    
    # Sort by total cost (descending)
    sorted_vehicles = sorted(vehicle_totals.items(), key=lambda x: x[1], reverse=True)
    total_cost_chart['labels'] = [item[0] for item in sorted_vehicles]
    total_cost_chart['data'] = [item[1] for item in sorted_vehicles]
    total_cost_chart['insights'] = {
        'most_expensive': {'vehicle': sorted_vehicles[0][0], 'amount': sorted_vehicles[0][1]},
        'most_economical': {'vehicle': sorted_vehicles[-1][0], 'amount': sorted_vehicles[-1][1]}
    }
    
    # 3. Category Breakdown Chart Data
    category_breakdown = {
        'labels': [],
        'data': [],
        'insights': {}
    }
    
    sorted_categories = sorted(category_totals.items(), key=lambda x: x[1], reverse=True)
    category_breakdown['labels'] = [item[0] for item in sorted_categories]
    category_breakdown['data'] = [item[1] for item in sorted_categories]
    category_breakdown['insights'] = {
        'top_category': sorted_categories[0][0],
        'top_category_percentage': (sorted_categories[0][1] / total_expense * 100) if total_expense > 0 else 0,
        'category_count': len(sorted_categories)
    }
    
    # 4. Monthly Trends Chart Data
    month_order = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    categories = list(set(item['type'] for item in vehicle_data))
    months = sorted(unique_months, key=lambda x: month_order.index(x))
    
    monthly_trends = {
        'labels': months,
        'datasets': [],
        'insights': {
            'months_tracked': len(months),
            'categories': len(categories)
        }
    }
    
    # Initialize monthly data structure
    monthly_data = {}
    for month in months:
        monthly_data[month] = {category: 0 for category in categories}
    
    # Fill monthly data
    for item in vehicle_data:
        monthly_data[item['month_name']][item['type']] += item['total_amount']
    
    # Create datasets for each category
    for category in categories:
        dataset = {
            'label': category,
            'data': [monthly_data[month][category] for month in months]
        }
        monthly_trends['datasets'].append(dataset)
    
    # 5. Cost Efficiency Chart Data (Average monthly cost per vehicle)
    vehicle_monthly_avg = {}
    vehicle_counts = {}
    
    for item in vehicle_data:
        if item['vehicle_number'] not in vehicle_monthly_avg:
            vehicle_monthly_avg[item['vehicle_number']] = 0
            vehicle_counts[item['vehicle_number']] = 0
        vehicle_monthly_avg[item['vehicle_number']] += item['total_amount']
        vehicle_counts[item['vehicle_number']] += 1
    
    efficiency_data = []
    for vehicle, total in vehicle_monthly_avg.items():
        avg_monthly = total / vehicle_counts[vehicle]
        efficiency_data.append({'vehicle': vehicle, 'avg_monthly': avg_monthly})
    
    # Sort by efficiency (ascending - most efficient first)
    efficiency_data.sort(key=lambda x: x['avg_monthly'])
    
    cost_efficiency = {
        'labels': [item['vehicle'] for item in efficiency_data],
        'data': [item['avg_monthly'] for item in efficiency_data],
        'insights': {
            'most_efficient': {'vehicle': efficiency_data[0]['vehicle'], 'amount': efficiency_data[0]['avg_monthly']},
            'least_efficient': {'vehicle': efficiency_data[-1]['vehicle'], 'amount': efficiency_data[-1]['avg_monthly']}
        }
    }
    
    # 6. Vehicle Comparison Matrix Data
    comparison_data = []
    for vehicle in unique_vehicles:
        vehicle_expenses = [item for item in vehicle_data if item['vehicle_number'] == vehicle]
        category_totals_vehicle = {category: 0 for category in categories}
        
        for expense in vehicle_expenses:
            category_totals_vehicle[expense['type']] += expense['total_amount']
        
        comparison_item = {
            'vehicle': vehicle,
            'categories': category_totals_vehicle,
            'total': sum(category_totals_vehicle.values())
        }
        comparison_data.append(comparison_item)
    
    vehicle_comparison = {
        'labels': [item['vehicle'] for item in comparison_data],
        'datasets': [],
        'insights': {
            'vehicles_compared': len(unique_vehicles),
            'expense_categories': len(categories)
        }
    }
    
    # Create datasets for each category
    for category in categories:
        dataset = {
            'label': category,
            'data': [item['categories'][category] for item in comparison_data]
        }
        vehicle_comparison['datasets'].append(dataset)
    
    # 7. Expense Distribution Chart Data
    expense_ranges = {
        'Under $100': 0,
        '$100-$300': 0,
        '$300-$500': 0,
        '$500-$1000': 0,
        'Over $1000': 0
    }
    
    for item in vehicle_data:
        amount = item['total_amount']
        if amount < 100:
            expense_ranges['Under $100'] += 1
        elif amount < 300:
            expense_ranges['$100-$300'] += 1
        elif amount < 500:
            expense_ranges['$300-$500'] += 1
        elif amount < 1000:
            expense_ranges['$500-$1000'] += 1
        else:
            expense_ranges['Over $1000'] += 1
    
    # Find most common range
    most_common_range = max(expense_ranges.items(), key=lambda x: x[1])
    
    expense_distribution = {
        'labels': list(expense_ranges.keys()),
        'data': list(expense_ranges.values()),
        'insights': {
            'total_transactions': len(vehicle_data),
            'most_common_range': most_common_range[0]
        }
    }
    
    # Return all prepared chart data
    return {
        'metrics': metrics,
        'total_cost_chart': total_cost_chart,
        'category_breakdown': category_breakdown,
        'monthly_trends': monthly_trends,
        'cost_efficiency': cost_efficiency,
        'vehicle_comparison': vehicle_comparison,
        'expense_distribution': expense_distribution
    }

##--------------------------------------------------------PURCHASE------------------------------------------------------------------------------------------------------------------

@app.route('/purchase', methods=['GET', 'POST'])
@login_required
def purchase():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    db = get_database()  
    cursor = db.cursor()
    user_access = get_employee_access_control(user['name'])

    from datetime import datetime
    cursor.execute(""" SELECT (SELECT COUNT(*) FROM created_pr WHERE status != 'Processed') AS unprocessed_pr_count,
        (SELECT COUNT(*) FROM created_pr WHERE DATE(PR_Date) = DATE('now')) AS today_pr_count,
        (SELECT COUNT(*) FROM created_pr WHERE strftime('%Y', PR_Date) = strftime('%Y', 'now')) AS current_year_pr_count;""")

    row = cursor.fetchone()
    pr_counts = { "unprocessed_pr_count": row[0], "today_pr_count": row[1], "current_year_pr_count": row[2]}

    cursor.execute("""SELECT (SELECT COUNT(*) FROM created_po WHERE status != 'Closed') AS unprocessed_po_count,
        (SELECT COUNT(*) FROM created_po WHERE DATE(PO_Date) = DATE('now')) AS today_po_count,
        (SELECT COUNT(*) FROM created_po WHERE strftime('%Y', PO_Date) = strftime('%Y', 'now')) AS current_year_po_count; """)

    row = cursor.fetchone()
    po_counts = { "unprocessed_po_count": row[0], "today_po_count": row[1], "current_year_po_count": row[2]}

    cursor.execute(""" SELECT status, COUNT(*) AS count FROM created_pr GROUP BY status; """)
    rows = cursor.fetchall()
    pr_stat_counts = {status: count for status, count in rows}
    pr_status_data = [{'status': key, 'count': value} for key, value in pr_stat_counts.items()]


    cursor.execute(""" SELECT status, COUNT(*) AS count FROM created_po GROUP BY status; """)
    rows = cursor.fetchall()
    po_stat_counts = {status: count for status, count in rows}
    po_status_data = [{'status': key, 'count': value} for key, value in po_stat_counts.items()]


    cursor.execute(""" SELECT do_staus, COUNT(*) AS count FROM created_po GROUP BY do_staus; """)
    rows = cursor.fetchall()
    do_stat_counts = {status: count for status, count in rows}
    do_status_data = [{'status': key, 'count': value} for key, value in do_stat_counts.items()]
    print("...........do_status_data...............",do_status_data)



    cursor.execute(""" SELECT cp.Supplier_Name, vd.company_name, COUNT(*) AS pr_count
        FROM created_pr cp
        LEFT JOIN vendors_details vd ON cp.Supplier_Name = vd.display_name
        GROUP BY cp.Supplier_Name, vd.company_name
        ORDER BY pr_count DESC; """)
    rows = cursor.fetchall()
    # Create a dict with Supplier_Name as key and a tuple of (company_name, count) as value
    supplier_counts = {supplier: (company, count) for supplier, company, count in rows}


    cursor.execute(""" SELECT created_by, COUNT(*) AS pr_count FROM created_pr GROUP BY created_by ORDER BY pr_count DESC; """)
    rows = cursor.fetchall()
    created_by_counts = {creator: count for creator, count in rows}

    cursor.execute(""" SELECT p.project_name, c.project_id, COUNT(*) AS pr_count
        FROM created_po c JOIN projects p ON c.project_id = p.id GROUP BY c.project_id ORDER BY pr_count DESC; """)
    rows = cursor.fetchall()

    project_pr_counts = [ {"project_id": project_id, "project_name": project_name, "count": pr_count} for project_name, project_id, pr_count in rows]

    print("...........pr_counts.......",pr_counts)
    print("............po_counts......",po_counts)
    print("......pr_stat_counts............",pr_stat_counts)
    print(".....po_stat_counts.............",po_stat_counts)
    print("......supplier_counts............",supplier_counts)
    print(".......created_by_counts...........",created_by_counts)
    print("........project_pr_counts..........",project_pr_counts)

    current_year = datetime.now().year
    print(".current_year.", current_year)

    # Get monthly count for PRs
    cursor.execute("""
        SELECT 
            CASE substr(PR_Date, 4, 2)
                WHEN '01' THEN 'Jan'
                WHEN '02' THEN 'Feb'
                WHEN '03' THEN 'Mar'
                WHEN '04' THEN 'Apr'
                WHEN '05' THEN 'May'
                WHEN '06' THEN 'Jun'
                WHEN '07' THEN 'Jul'
                WHEN '08' THEN 'Aug'
                WHEN '09' THEN 'Sep'
                WHEN '10' THEN 'Oct'
                WHEN '11' THEN 'Nov'
                WHEN '12' THEN 'Dec'
            END AS month,
            COUNT(*)
        FROM created_pr
        WHERE substr(PR_Date, 7, 2) = ?
        GROUP BY substr(PR_Date, 4, 2);
    """, (str(current_year)[2:],))
    pr_monthly_count = cursor.fetchall()

    cursor.execute("""
        SELECT 
            CASE substr(PO_Date, 4, 2)
                WHEN '01' THEN 'January'
                WHEN '02' THEN 'February'
                WHEN '03' THEN 'March'
                WHEN '04' THEN 'April'
                WHEN '05' THEN 'May'
                WHEN '06' THEN 'June'
                WHEN '07' THEN 'July'
                WHEN '08' THEN 'August'
                WHEN '09' THEN 'September'
                WHEN '10' THEN 'October'
                WHEN '11' THEN 'November'
                WHEN '12' THEN 'December'
            END AS month,
            COUNT(*)
        FROM created_po
        WHERE substr(PO_Date, 7, 2) = ?
        GROUP BY substr(PO_Date, 4, 2);
    """, (str(current_year)[2:],))
    po_monthly_count = cursor.fetchall()

    # Helper function to convert data into the desired format
    def extract_labels_and_values(data):
        labels = [item[0] for item in data]
        values = [item[1] for item in data]
        return labels, values

    # Extract labels and values for monthly counts of PRs and POs
    pr_monthly_labels, pr_monthly_values = extract_labels_and_values(pr_monthly_count)
    po_monthly_labels, po_monthly_values = extract_labels_and_values(po_monthly_count)

    print("...........pr_monthly_labels...............",pr_monthly_labels)
    print("..............pr_monthly_values............",pr_monthly_values)
    print("..........po_monthly_labels................",po_monthly_labels)
    print("...........po_monthly_values...............",po_monthly_values)

    dept_map = {
        "2001": "Mechanical",
        "2002": "Electrical",
        "2003": "Instrument",
        "2004": "PLC HW",
        "2005": "Panel HW",
        "2006": "Consumbls",
        "2007": "Tools",
        "2008": "Civil",
        "2009": "Computer",
        "3001": "Scaffold",
        "3002": "Program",
        "3003": "E&I Fab",
        "3004": "Mech Fab",
        "3005": "Manpower",
        "3006": "LEW",
        "3007": "Calibration",
        "3008": "Equip Rent",
        "3009": "Servicing",
        "3010": "Others",
        "504": "Vehicle",
        "510": "Training",
        "511": "Medical",
        "512": "Utilities",
        "513": "Travel",
        "514": "Safety",
        "515": "Office",
        "517": "Calibration",
        "519": "Entmt ",
        "520": "Others"
    }

    query = """
        SELECT substr(PO_number, instr(PO_number, '-') + 1, instr(substr(PO_number, instr(PO_number, '-') + 1), '-') - 1 ) AS department_code,
            SUM(CAST(total AS REAL)) AS total_amount
        FROM po_items
        GROUP BY department_code
        ORDER BY department_code;
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    depart_totals = []
    unknown_total = 0.0

    for code, total in rows:
        if code in dept_map:
            dept_name = dept_map[code]
            depart_totals.append({"department_code": code, "department_name": dept_name, "total_amount": round(total, 2)})
        else:
            # Accumulate totals for unknown codes
            unknown_total += total

    # Add the combined unknown entry if there was any unknown total
    if unknown_total > 0:
        depart_totals.append({"department_code": "Unknown", "department_name": "Unknown", "total_amount": round(unknown_total, 2)})

    print(depart_totals)
    categories = { "2000": {"name": "Material", "range": range(2001, 2010)},
        "3000": {"name": "Sub Contract", "range": range(3001, 3011)},
        "500": {"name": "Others", "range": list(range(504, 521)) + [500]},
        "4000": {"name": "Site", "range": []} }

    category_sums = {key: 0 for key in categories.keys()}

    for item in depart_totals:
        try:
            code_str = item.get("department_code")
            total = item.get("total_amount", 0) or 0

            code_int = int(code_str) if code_str is not None else None
            total = float(total) if total is not None else 0

            assigned = False
            if code_int is not None:
                for cat_code, cat_info in categories.items():
                    if code_int in cat_info["range"]:
                        category_sums[cat_code] += total
                        assigned = True
                        break
            if not assigned:
                category_sums["500"] += total
        except Exception as e:
            print(f"Error processing item {item}: {e}")
            # Optional: you can also log these errors

    category_list = []
    for cat_code, total in category_sums.items():
        total = float(total) if total is not None else 0
        category_list.append({ "category_code": cat_code, "category_name": categories[cat_code]["name"], "total_amount": round(total, 2)})

    print(category_list)





    return render_template('admin_templates/purchase/pur_index.html', user=user, department_code=department_code,user_access=user_access,
                               pr_counts = pr_counts, po_counts = po_counts, pr_stat_counts = pr_status_data, po_stat_counts = po_status_data, supplier_counts = supplier_counts,
    created_by_counts = created_by_counts, project_pr_counts = project_pr_counts, pr_monthly_labels = pr_monthly_labels, pr_monthly_values = pr_monthly_values,
    po_monthly_labels = po_monthly_labels, po_monthly_values = po_monthly_values, category_list = category_list, depart_totals=depart_totals, do_status_data=do_status_data)

@app.route('/pur_suppliers', methods=["POST", "GET"])
@login_required
def pur_suppliers():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM vendors_details ORDER BY id DESC')
    vendors = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
    max_client_code_row = cursor.fetchone()

    if max_client_code_row:
        max_client_code = max_client_code_row[0]
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1
    else:
        new_numeric_part = 1  

    new_vendor_code = f'V - {new_numeric_part:04d}'

    if request.method == "POST":

        if 'Delete' in request.form:
            vendordata = request.form.getlist('vendordata[]')
            db = get_database()
            cursor = db.cursor()
            try:
                for claim_str in vendordata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM vendors_details WHERE id = ?', (claim_id,))
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            return redirect(url_for('pur_suppliers'))
        
        vendor_code = request.form['vendor_code']
        reg_no = request.form['reg_no']
        company_name = request.form['company_name']
        display_name = request.form['display_name']
        office_no = request.form['office_no']
        website = request.form['website']
        billing_address1 = request.form['billing_address1']
        billing_address2 = request.form['billing_address2']
        city = request.form['city']
        postcode = request.form['postcode']
        country = request.form['country']
        state = request.form['state']
        contact1 = request.form['contact1']
        email1 = request.form['email1']
        mobile1 = request.form['mobile1']
        contact2 = request.form['contact2']
        email2 = request.form['email2']
        mobile2 = request.form['mobile2']
        contact3 = request.form['contact3']
        email3 = request.form['email3']
        mobile3 = request.form['mobile3']
        bank_name = request.form['bank_name']
        tax_id = request.form['tax_id']
        branch_details = request.form['branch_details']
        currency = request.form['currency']
        pay_terms = request.form['pay_terms']
        account_no = request.form['account_no']
        swift = request.form['swift']
        ifsc = request.form['ifsc']
        product_catgory = request.form['Product_Category']
        brand = request.form['Brands']
        Details = request.form['Details']

        try:
            # Check if vendor code exists
            cursor.execute('SELECT id FROM vendors_details WHERE vendor_code = ?', (vendor_code,))
            existing_vendor = cursor.fetchone()

            if existing_vendor:
                # Update existing vendor
                vendor_id = existing_vendor[0]
                cursor.execute( '''UPDATE vendors_details SET reg_no = ?, company_name = ?, display_name = ?, office_no = ?, website = ?, billing_address1 = ?,
                                billing_address2 = ?, city = ?, postcode = ?, country = ?, state = ?, contact1 = ?, email1 = ?, mobile1 = ?, contact2 = ?, email2 = ?,
                                mobile2 = ?, contact3 = ?, email3 = ?, mobile3 = ?, bank_name = ?, tax_id = ?, branch_details = ?, currency = ?, pay_terms = ?, 
                               account_no = ?, swift = ?, ifsc = ?, product_catgory = ?, brand = ?, Details = ?  WHERE id = ?''',
                                [reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, 
                                 contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency,
                                   pay_terms, account_no, swift, ifsc,product_catgory, brand,Details, vendor_id] )
                db.commit()
                flash(f"Vendor details for '{company_name}' have been updated.", 'success')
            
            else:
                # Insert new vendor
                cursor.execute(
                    '''INSERT INTO vendors_details (vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city,
                      postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, 
                      currency, pay_terms, account_no, swift, ifsc, product_catgory, brand, Details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    [vendor_code, reg_no, company_name, display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1,
                      email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, 
                      swift, ifsc,product_catgory, brand, Details])
                db.commit()
                flash(f"Vendor details for '{company_name}' have been successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add/update vendor details. Please try again.", 'error')

        return redirect(url_for('pur_suppliers'))
    
    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT COUNT(*) FROM vendors_details")
    total_vendors = cursor.fetchone()[0]
    return render_template('admin_templates/purchase/pur_suppliers.html',user_access=user_access, user=user,vendors=vendors,department_code=department_code,
                          total_vendors=total_vendors, new_vendor_code=new_vendor_code)

@app.route('/pur_suppliers_del', methods=['GET'])
@login_required
def pur_suppliers_del():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    id = request.args.get('id')
    db = get_database()
    db.execute("DELETE FROM vendors_details WHERE id = ?", (id,))
    db.commit()
    
    flash('Client details deleted successfully', 'success')
    return redirect(url_for('pur_suppliers'))

@app.route('/pur_po', methods=['GET', 'POST'])
def pur_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    if request.method == 'POST':
        PO_Print = request.form.get ('PO_Print')
        PO_Delete = request.form.get('PO_Delete')
        
        if PO_Delete:
            # Step 1: Get the PO_no from the 'created_po' table using the 'id'
            cursor.execute('SELECT PO_no FROM created_po WHERE id = ?', (PO_Delete,))
            result = cursor.fetchone()

            if result:
                PO_no = result[0]

                # Step 2: Set the total to '0' in both tables instead of deleting
                cursor.execute('UPDATE po_items SET total = "0" WHERE PO_number = ?', (PO_no,))
                cursor.execute('UPDATE created_po SET total = "0" WHERE id = ?', (PO_Delete,))

                cursor.execute('UPDATE created_po SET status = "Canceled" WHERE id = ?', (PO_Delete,))
                cursor.execute('UPDATE manual_entry SET total = 0 WHERE cost_center_id = ?', (PO_no,))

                show = 'po'
            else:
                # If no matching PO_no found, just set the total to 0 in the 'created_po' table
                cursor.execute('UPDATE created_po SET total = "0" WHERE id = ?', (PO_Delete,))

            # Commit the changes to the database
            db.commit()
            return redirect(url_for('pur_po'))

        if PO_Print:
            show = 'po'
            cursor.execute('SELECT PO_no FROM created_po WHERE id = ?', (PO_Print,))
            PO_number = cursor.fetchone()

            if PO_number:
                PO_number = PO_number[0]
                cursor.execute('SELECT * FROM created_po WHERE id = ?', (PO_Print,))
                po_details = cursor.fetchone()

                cursor.execute(''' SELECT Part_No, item, quantity, uom, Unit_Price, total, GST FROM po_items WHERE PO_number = ? ''', (PO_number,))
                po_items = cursor.fetchall()
             
                if po_items:
                    data_dict = []
                    total_sum = 0
                    po_gst_value = po_items[0]['GST']  

                    for index, item in enumerate(po_items):  

                        unit_price = float(item[4])
                        total_value = float(item[5])

                        formatted_unit_price = "{:,.2f}".format(unit_price)
                        formatted_total_value = "{:,.2f}".format(total_value)

                        # Safely convert other values to strings
                        item_dict = {'index': str(index + 1), 'Part_No': str(item[0]), 'item': str(item[1]),'quantity': str(item[2]), 
                                     'uom': str(item[3]),'Unit_Price': formatted_unit_price,  'total': formatted_total_value,  'GST': str(item[6]) }

                        data_dict.append(item_dict)
                        total_sum += total_value

                    # Step 1: Discount
                    # Step 1: Discount
                    discount_percent = float(po_details['Discount'] or 0.0)  # Ensure it's a float
                    discount_value = total_sum * (discount_percent / 100)

                    # Step 2: Apply discount to get taxable amount
                    taxable_amount = total_sum - discount_value

                    # Step 3: GST
                    if po_gst_value != 1.0:
                        gst_amount = taxable_amount * (po_gst_value / 100)
                    else:
                        po_gst_value = 0.0
                        gst_amount = 0.0

                  
                    final_total = taxable_amount + gst_amount

                    # Round the values to 2 decimal places
                    total_sum = round(total_sum, 2)
                    discount_value = round(discount_value, 2)
                    gst_amount = round(gst_amount, 2)
                    final_total = round(final_total, 2)

                    # Convert the rounded values to international numbering format and then to string
                    total_sum_str = "{:,.2f}".format(total_sum)
                    discount_value_str = "{:,.2f}".format(discount_value)
                    gst_amount_str = "{:,.2f}".format(gst_amount)
                    final_total_str = "{:,.2f}".format(final_total)

                    total_sum = "{:,.2f}".format(total_sum)
                    print("........po_details.............",po_details)
                    pdf_file = new_po_pdf(data_dict, total_sum_str, gst_amount_str, final_total_str, po_gst_value, po_details,discount_value_str)

                    if pdf_file:
                        db.commit()  # Save changes if any
                        return send_file(pdf_file, download_name=f"{po_details['PO_no']}.pdf", as_attachment=True, mimetype='application/pdf')

                else:
                    flash("No items found for the selected PO number.")
                    return redirect(url_for('pur_po'))
            
            else:
                flash("No PO number found for the given ID.")
                return redirect(url_for('pur_po'))
            return redirect(url_for('pur_po'))

    # Fetch all POs where the project status is not 'Closed'
    cursor.execute("""
        SELECT cp.*
        FROM created_po cp
        JOIN projects p ON cp.project_id = p.id
        WHERE p.status != 'Closed'
        ORDER BY cp.id DESC
    """)
    po_query = cursor.fetchall()

    
    columns = [desc[0] for desc in cursor.description]
    merged_po_data = [dict(zip(columns, po)) for po in po_query]

    # Process each PO entry
    seen_po_no = set()
    final_po_data = []
    from datetime import datetime, timedelta

    for row in merged_po_data:
        po_no = row['PO_no']
        project_id = row['project_id']  

        if po_no not in seen_po_no:
            # Check if the user is the PM of the project
            cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
            pm_result = cursor.fetchone()
            row['pm'] = 'Yes' if pm_result and user['name'] == pm_result[0] else 'No'
            
            # Get total and GST calculations from po_items
            cursor.execute("SELECT SUM(total), AVG(GST) FROM po_items WHERE PO_number = ?", (po_no,))
            total, gst_percent = cursor.fetchone()
            total = total if total else 0
            gst_percent = gst_percent if gst_percent else 0  
            gst_amount = (total * gst_percent / 100) if gst_percent and gst_percent != 1 else 0

            cursor.execute("SELECT Discount FROM created_po WHERE PO_no = ?", (po_no,))
            discount_row = cursor.fetchone()
            discount_percent = float(discount_row[0]) if discount_row and discount_row[0] else 0
            discount_amount = total * (discount_percent / 100)
            amount_after_discount  = total - discount_amount
            exchange_rate = float(row.get('Exchange_rate', 1.0) or 1.0)
            gst_amount = (amount_after_discount  * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
            total_with_gst = amount_after_discount  + gst_amount
            row['amount'] = round(amount_after_discount / exchange_rate, 2)
            row['GST'] = round(gst_amount / exchange_rate, 2)
            row['total'] = round(total_with_gst / exchange_rate, 2)

            po_date_str = row['PO_Date']  
            lead_time_str = row.get('leat_time', '')  # Note: spelling of 'leat_time'
            # print(".....lead_time_str............",lead_time_str)

            if po_date_str and lead_time_str:
                po_date = datetime.strptime(po_date_str, '%y-%m-%d')
                lead_time = parse_po_lead_time(lead_time_str)

                if lead_time:
                    delivery_date = po_date + lead_time
                    row['delivery_date'] = delivery_date.strftime('%y-%m-%d')
                else:
                    row['delivery_date'] = ''
            else:
                row['delivery_date'] = ''


            final_po_data.append(row)
            seen_po_no.add(po_no)

    grouped_df = pd.DataFrame(final_po_data)
    grouped_df = grouped_df.sort_values(by='id', ascending=False)

    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    return render_template('admin_templates/purchase/pur_po.html', user=user, department_code=department_code, user_access=user_access, grouped_df=grouped_df,
    Supplier_Names=Supplier_Names, gst=gst)

@app.route('/pur_genpr', methods=["POST", "GET"])
@login_required
def pur_genpr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    user_access = get_employee_access_control(user['name'])

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate_pr':

            project_id = request.form.get('project_id', type=int)
            Supplier_Name = request.form.get('Supplier_Name')
            query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
            cursor.execute(query, (Supplier_Name,))
            result = cursor.fetchone()

            if result:
                Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
                Supplier_address3 = f"{country}, {city} - {postcode}"

            Attn = request.form.get('Attn')
            leat_time = request.form.get('leat_time')
            Unit = request.form.get('Unit')
            leat_time =  str(leat_time) + ' ' + Unit
            Contact = request.form.get('Contact')
            phone_number = request.form.get('number')
            PR_Date = request.form.get('PR_Date') 
            Quote_Ref = request.form.get('Quote_Ref')
            Expenses = request.form.get('code_number')
            comments = request.form.get('comments')
            Delivery = request.form.get('Delivery')
            Address_Line1 = request.form.get('Address_Line1')
            Address_Line2 = request.form.get('Address_Line2')
            Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
            Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
            original_creater = user['name']
            project_id = request.form.get('project_id')
            gst_checkbox = request.form.get('gstCheckbox')
            part_nos = request.form.getlist('part_no[]')
            descriptions = request.form.getlist('description[]')
            uoms = request.form.getlist('uom[]')
            excepted_dates = request.form.getlist('excepted_date[]')  # Added to extract expected dates
            quantities = request.form.getlist('quantity[]')
            unit_prices = request.form.getlist('unit_price[]')
            cursor.execute("SELECT MAX(id) FROM created_pr")

            result = cursor.fetchone()
            if result and result[0] is not None:
                max_pr = int(result[0])
            else:
                max_pr = 0
            sequential_number = max_pr + 1
            PR_no = f"{project_id}-{Expenses}-{sequential_number:04}"
            attachment = request.files.get('attachment')  # Get the attachment from the form

            if attachment:
                upload_dir = 'docment_data/PR Quotes'
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir) 

                file_name, file_extension = os.path.splitext(attachment.filename) 
                new_filename = f"{PR_no}{file_extension}" 
                print("...........new_filename......",new_filename)
                filename = os.path.join(upload_dir, new_filename)
                attachment.save(filename)
                print(f"File uploaded successfully: {filename}")
            
            else:
                new_filename = None  # No file uploaded
                print("No file uploaded.")

            try:
                cursor.execute('''INSERT INTO created_pr (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms, Currency, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments, original_creater) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                            (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, Contact, Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms, Currency, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments, original_creater))
                db.commit()
                print(f"Insert successful: PR_no: {PR_no}, project_id: {project_id}, Supplier_Name: {Supplier_Name}")
            except Exception as e:
                print(f"Error occurred: {e}")

            # Fetch the latest GST value
            cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
            latest_gst = cursor.fetchone()  # Fetch the first result
            latest_gst_value = latest_gst[0] if latest_gst else 1  
            items1 = []
            for part_no, description, uom, excepted_date, quantity, unit_price in zip(part_nos, descriptions, uoms, excepted_dates, quantities, unit_prices):
                total = float(quantity) * float(unit_price)
                rounded_total = round(total, 2)
                item = {'project_id': project_id,'pr_number': PR_no,'part_no': part_no,'description': description,'uom': uom,'quantity': float(quantity),'unit_price': float(unit_price),'total': rounded_total,'excepted_date': excepted_date,}
                item['gst'] = latest_gst_value  if gst_checkbox else 1
                items1.append(item)

            if items1:
                for item in items1:
                    cursor.execute("""INSERT INTO pr_items ( project_id, pr_number, Part_No,item,  quantity,  uom,  Unit_Price, GST,  total, excepted_date, status)  
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                        (item['project_id'],item['pr_number'],item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'],item['gst'], item['total'], item['excepted_date'], 'Open' ))
                db.commit()

                cursor.execute("UPDATE created_pr SET status = 'Created' WHERE PR_no = ?", (PR_no,))
                db.commit()
                cursor.execute("SELECT pm, project_name FROM projects WHERE id = ?", (project_id,))
                result = cursor.fetchone()
                if result:
                    pm = result[0] #pm
                    user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (pm,))
                    mail_to_row = user_cur.fetchone()
                    if mail_to_row:
                        mail_to = mail_to_row['name']
                    else:
                        mail_to = 'sairam@gmail.com'
                project_name = result[1] #project name
                created_by = user['name']

                query = """  SELECT name, username FROM admin_user WHERE department_code IN (14, 1000) OR secondary_role_code = 14; """
                # Execute the query
                cursor.execute(query)
                results = cursor.fetchall()
                # Optionally print the Employee_IDs and names
                employee_emails = [row[1] for row in results] 
                if mail_to not in employee_emails:  # Optionally, check for duplicates
                    employee_emails.append(mail_to)

                import re
                # Regular expression to validate email addresses
                email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                # Filter valid email addresses
                valid_emails = [email for email in employee_emails if re.match(email_regex, email)]
                # Optionally print or use the valid_emails list
                if valid_emails:
                    print("Valid Emails:", valid_emails)
                    # PR_Created_Notification(valid_emails,project_name,project_id, created_by, PR_no)


                flash('PR generated successfully! Please wait for Approval.', 'pur_pr_genrated')
                db.commit()

            else:
                cursor.execute("DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?", (PR_no, project_id))
                db.commit()

            db.commit()
            return redirect(url_for('pur_genpr'))
          
    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")
    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    query = '''SELECT id AS id, project_name FROM projects WHERE status != 'Closed' ORDER BY id DESC; '''
    cursor.execute(query)
    projects = cursor.fetchall()
    db.commit()

    return render_template('admin_templates/purchase/pur_genpr.html', user=user, 
                         user_access=user_access,
                         Supplier_Names=Supplier_Names,department_code=department_code, is_pm=is_pm
                         ,usernames=usernames, projects=projects,current_date=formatted_date)

@app.route('/docment_data/PR Quotes/<path:filename>')
def view_pr_qoute_file(filename):
    directory = os.path.abspath(r'docment_data\PR Quotes')

    # List of common file extensions
    extensions = [
        '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  
        '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',  
        '.html', '.htm', '.xml', '.json', '.zip', '.tar', '.gz', '.rar',  
        '.mp3', '.wav', '.ogg', '.mp4', '.avi', '.mkv', '.mov', '.webm',  
        '.svg', '.eps', '.ai', '.psd', '.indd', '.epub', '.mobi', '.azw3',  
        '.pptx', '.key', '.xlsx', '.ods', '.json', '.yaml', '.md', '.rst',  
        '.exe', '.msi', '.dmg'
    ]

    # Check if the exact filename exists first
    exact_path = os.path.join(directory, filename)
    if os.path.exists(exact_path):
        print(f"File found: {exact_path}")
        return send_from_directory(directory, filename, as_attachment=False)

    # Try adding different extensions
    for ext in extensions:
        file_path = os.path.join(directory, filename + ext)
        print(f"Checking file path: {file_path}")
        
        if os.path.exists(file_path):
            print(f"File found: {file_path}")
            return send_from_directory(directory, filename + ext, as_attachment=False)
    
    return "File not found", 404

def send_pr_to_po_emial(valid_emails, PR_no, project_id, issued_by, PO_no):
    """Send emails asynchronously to avoid blocking the main thread."""
    import re
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    valid_emails = [email for email in valid_emails if re.match(email_regex, email)]

    if valid_emails:
        print(".......valid_emails......",valid_emails)
        # PR_Processed_Notification(valid_emails, PR_no, project_id, issued_by, PO_no)

@app.route('/approve_po', methods=['POST'])
def approve_po():
    data = request.get_json()
    PR_no = data.get('PR_no')
    db = get_database()
    cursor = db.cursor()
    user = get_current_user()
    user_name = user['name']

    # Update PR status to Processed
    cursor.execute('UPDATE created_pr SET status = ? WHERE PR_no = ?', ('Processed', PR_no))
    # Explicitly select all columns from created_pr by name
    cursor.execute('''
        SELECT id, PR_no, project_id, Supplier_Name, phone_number, PR_Date, created_by,
            Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms,
            Currency, status, total, Attn, Supplier_address1, Supplier_address2,
            Supplier_address3, Company_name, leat_time, comments, approved_by,
            original_creater, filename, Exchange_rate, Discount
        FROM created_pr
        WHERE PR_no = ?
    ''', (PR_no,))

    # Fetch and unpack values into named variables
    (id, PR_no, project_id, Supplier_Name, phone_number, PR_Date, created_by,
    Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms,
    Currency, status, total, Attn, Supplier_address1, Supplier_address2,
    Supplier_address3, Company_name, leat_time, comments, approved_by,
    original_creater, filename, Exchange_rate, Discount) = cursor.fetchone()

    print(id, PR_no, project_id, Supplier_Name, phone_number, PR_Date, created_by,
    Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms,
    Currency, status, total, Attn, Supplier_address1, Supplier_address2,
    Supplier_address3, Company_name, leat_time, comments, approved_by,
    original_creater, filename, Exchange_rate, Discount)
    # Generate PO number
    from datetime import datetime, timedelta

    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")
    cursor.execute("SELECT MAX(id) FROM created_po")
    result = cursor.fetchone()
    sequential_number = (int(result[0]) + 1) if result and result[0] is not None else 1
    PO_no = f"{project_id}-{Expenses}-{sequential_number:04}"

    # Insert new PO record
    cursor.execute('''INSERT INTO created_po (PO_no, project_id, Supplier_Name, phone_number, PO_Date, created_by, Quote_Ref, 
                      Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms, Currency, status, total, Attn, 
                      Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments, approved_by, 
                      PR_no_ref, PO_Issued_by, do_staus, filename, Exchange_rate, Discount) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (PO_no, project_id, Supplier_Name, phone_number, formatted_date, created_by, Quote_Ref, Expenses, Delivery,
                    Address_Line1, Address_Line2, Payment_Terms, Currency, 'Issued', total, Attn, Supplier_address1,
                    Supplier_address2, Supplier_address3, Company_name, leat_time, comments, approved_by, PR_no, user_name, 'Open', filename, Exchange_rate, Discount))

    # Insert items into po_items
    cursor.execute("SELECT * FROM pr_items WHERE pr_number = ? AND project_id = ?", (PR_no, project_id))
    temp_items = cursor.fetchall()
    for item in temp_items:
        cursor.execute('''INSERT INTO po_items (project_id, PO_number, Part_No, item, quantity, uom, Unit_Price, total, GST, excepted_date, status) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (item['project_id'], PO_no, item['Part_No'], item['item'], item['quantity'], item['uom'], item['Unit_Price'],
                        item['total'], item['GST'], item['excepted_date'], item['status']))
        
        # Convert total (as string with commas) to float
        total_sum = float(item['total'].replace(',', ''))

        # Calculate original cost
        cost = item['quantity'] * item['Unit_Price']

        # Apply discount (if any) to the total
        discount_percent = Discount if Discount else 0  # from unpacked pr_details
        discount_amount = total_sum * (discount_percent / 100)
        total_after_discount = total_sum - discount_amount

        # Insert with adjusted total
        cursor.execute('''INSERT INTO manual_entry (project_id, username, department_code, cost, gst_value, total, cost_center_id, Exchange_rate,Discount) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project_id, user_name, Expenses, cost, item['GST'], total_after_discount, PO_no, Exchange_rate, Discount))


    db.commit()

    # Fetch emails of employees with access control as 'pur_purchaser'
    cursor.execute("SELECT name, username  FROM admin_user  WHERE department_code IN (14, 1000) OR secondary_role_code IN (14, 1000);")
    all_emails_set = {row[0] for row in cursor.fetchall()}
    
    # Add emails of created_by and approved_by users
    for username in [created_by, approved_by]:
        user_data = db.execute('SELECT name FROM admin_user WHERE username = ?', (username,)).fetchone()
        if user_data:
            all_emails_set.add(user_data[0])
    
    valid_emails = [email for email in all_emails_set if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)]
    
    if valid_emails:
        issued_by = user_name
        # email_thread = threading.Thread(target=send_pr_to_po_emial, args=(valid_emails, PR_no, project_id, issued_by, PO_no))
        # email_thread.start()
    
    return jsonify({'message': 'PO Issued successfully!'})

@app.route('/pur_purchase', methods=['GET', 'POST'])
def pur_purchase():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    # Get all project IDs where status is not 'Closed'
    cursor.execute("SELECT id FROM projects WHERE status != 'Closed'")
    active_project_ids = [row[0] for row in cursor.fetchall()]

    # Fetch all PRs for those active projects
    cursor.execute(f""" SELECT * FROM created_pr  WHERE project_id IN ({','.join(['?'] * len(active_project_ids))})  ORDER BY id DESC""", active_project_ids)
    pr_query = cursor.fetchall()

    columns = [desc[0] for desc in cursor.description]
    merged_pr_data = [dict(zip(columns, pr)) for pr in pr_query]

    for row in merged_pr_data:
        pr_no = row['PR_no']
        project_id = int(row.get('project_id', 0)) if row.get('project_id') else None
        cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
        pm_result = cursor.fetchone()
        row['pm'] = 'Yes' if pm_result and user['name'] == pm_result[0] else 'No'
        cursor.execute("SELECT SUM(total), AVG(GST) FROM pr_items WHERE pr_number = ?", (pr_no,))
        total, gst_percent = cursor.fetchone()
        total = float(total) if total else 0
        gst_percent = float(gst_percent) if gst_percent else 0

        cursor.execute("SELECT Discount FROM created_pr WHERE PR_no = ?", (pr_no,))
        discount_row = cursor.fetchone()
        discount_percent = float(discount_row[0]) if discount_row and discount_row[0] else 0
        discount_amount = total * (discount_percent / 100)
        amount_after_discount  = total - discount_amount
        exchange_rate = float(row.get('Exchange_rate', 1.0) or 1.0)
        gst_amount = (amount_after_discount  * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
        total_with_gst = amount_after_discount  + gst_amount
        row['amount'] = round(amount_after_discount / exchange_rate, 2)
        row['GST'] = round(gst_amount / exchange_rate, 2)
        row['total'] = round(total_with_gst / exchange_rate, 2)
        row['id'] = row.get('id', None)

    grouped_df = pd.DataFrame(merged_pr_data)

    # ✅ Check if 'id' column exists before sorting
    if 'id' in grouped_df.columns:
        grouped_df = grouped_df.sort_values(by='id', ascending=False)
    # print("....grouped_df............",grouped_df)
    cursor.execute('SELECT display_name FROM vendors_details')
    # Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    query = '''SELECT id FROM projects WHERE status != 'Closed' ORDER BY id DESC;'''
    cursor.execute(query)
    projects = [row[0] for row in cursor.fetchall()]  # Now a flat list like [101, 100, 99, ...]

    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    return render_template('admin_templates/purchase/pur_purchase.html', user=user, department_code=department_code, user_access=user_access, 
                           projects=projects, Supplier_Names=Supplier_Names,grouped_df=grouped_df,usernames=usernames,gst=gst)

from flask import request, jsonify

@app.route('/get_item_suggestions')
def get_item_suggestions():
    search = request.args.get('q', '').strip()
    db = get_database()
    cursor = db.cursor()

    if not search:
        return jsonify([])

    cursor.execute("""
        SELECT 
            pi.item, 
            pi.Unit_Price, 
            cp.Supplier_Name, 
            cp.PR_no,
            cp.created_by,
            cp.PR_Date
        FROM pr_items pi
        JOIN created_pr cp ON pi.project_id = cp.project_id
        WHERE pi.item LIKE ?
        GROUP BY pi.item
        LIMIT 10
    """, ('%' + search + '%',))

    results = [
        {
            "item": row["item"],
            "Unit_Price": row["Unit_Price"],
            "Supplier_Name": row["Supplier_Name"],
            "PR_no": row["PR_no"],
            "created_by": row["created_by"],
            "PR_Date": row["PR_Date"]
        }
        for row in cursor.fetchall()
    ]

    return jsonify(results)


@app.route('/delete_pr', methods=['POST'])
def delete_pr():
    pr_id = request.form.get('pr_id')  # Get PR_no from the form
    db = get_database()
    cursor = db.cursor()

    try:
        print(f"Deleting PR ID: {pr_id}")  # Debug log
        # Delete from database
        cursor.execute("DELETE FROM created_pr WHERE PR_no = ?", (pr_id,))
        cursor.execute("DELETE FROM pr_items WHERE pr_number = ?", (pr_id,))
        db.commit()

        flash("PR deleted successfully", "success")  # Flash message
        return redirect(url_for('pur_purchase'))  # Redirect back to the page

    except Exception as e:
        print("Deletion failed:", e)
        flash("Failed to delete PR", "danger")
        return redirect(url_for('pur_purchase'))

import unicodedata
import re

def normalize_text(text):
    if isinstance(text, str):
        try:
            text = text.replace("\ufb01", "fi").replace("\ufb02", "fl")
            text = text.replace("\ufb03", "ffi").replace("\ufb04", "ffl")
            text = text.replace("”", "\"").replace("“", "\"")
            text = text.replace("‘", "'").replace("’", "'")
            text = text.replace("–", "-").replace("—", "-")  # En dash & Em dash to hyphen
            text = re.sub(r'[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]', '', text)
            text = unicodedata.normalize('NFKD', text)
        except Exception as e:
            print(f"Error during normalization: {e}. Proceeding with text as is.")
            pass
    return text

def new_po_pdf(data_dict, total_sum_str, gst_amount_str, final_total_str, gst, po_details,discount_value_str):
    if isinstance(po_details, sqlite3.Row):
        po_details = dict(po_details)
    
    if isinstance(data_dict, sqlite3.Row):
        data_dict = dict(data_dict)

    if isinstance(data_dict, list):
        data_dict = [ {k: normalize_text(v) for k, v in item.items()} for item in data_dict]
    else:
        data_dict = {k: normalize_text(v) for k, v in data_dict.items()}

    po_details = {k: normalize_text(v) for k, v in po_details.items()}
    pdf_output = BytesIO()
    pdf = PDF(data_dict, total_sum_str, gst_amount_str, final_total_str, gst, po_details,discount_value_str )  
    pdf.add_page()  
    pdf.body()
    pdf_output.write(pdf.output(dest='S').encode('latin1', errors='replace'))
    pdf_output.seek(0)  

    return pdf_output  

class PDF(FPDF):

    def __init__(self, data_dict, total_sum_str,gst_amount_str,final_total_str,gst, po_details,discount_value_str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.po_details = po_details
        self.final_total_str = final_total_str
        self.total_sum_str = total_sum_str
        self.gst_amount_str = gst_amount_str
        self.discount_value_str = discount_value_str
        self.gst = gst
        self.data_dict = data_dict
        self.max_y = 0
        self.page_height = 292 
        self.set_font('helvetica', '', 10)
        self.alias_nb_pages() # <--- Make sure this line is present

    def header(self):
        self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
        self.rect(2, 2 , 205, 292)

        image_path = os.path.join('static', 'CENTROID Logo.jpg')  # Replace with your actual static path
        # image_path = os.path.join('/home/CES/mysite/static', 'CENTROID Logo.jpg')
        self.image(image_path, 145, 5, 50, 8) 
        self.set_font('helvetica', '', 12)
        self.set_xy(2, 5)  # Start text at the leftmost side of the page

        # Company details
        self.cell(0, 6, 'Centroid Engineering Solutions Pte Ltd', ln=True)
        self.set_x(2)  # Reset x-coordinate after each line break
        self.cell(0, 6, 'Co Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'GST Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, '11, Woodlands Close, #07-10', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'Singapore - 737853', ln=True)

        # Move the title to be in between the logo and the details
        self.set_xy(25, 28)  # Adjust position of the title (center between details and logo)
        self.set_font('helvetica', 'B', 20)  # Title in bold
        self.cell(0, 10, 'PURCHASE ORDER', ln=True, align='C')  # Title in the center

        self.line(2, 39, 207, 39)  # Line from x=10 to x=200 at y=40

        from datetime import datetime, timedelta

        try:
            po_date = datetime.strptime(self.po_details['PO_Date'], '%Y-%m-%d')
            formatted_po_date = po_date.strftime('%d-%m-%Y')
        except ValueError:
            formatted_po_date = self.po_details['PO_Date']  # Fallback if date parsing fails


        # Client Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 40)
        self.cell(0, 6, 'Client', ln=False)
        self.set_xy(19, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(21, 40)
        self.cell(0, 6, self.po_details['Company_name'], ln=True)

        # Client Address
        self.set_x(21)
        self.cell(0, 6, self.po_details['Supplier_address1'], ln=True)
        self.set_x(21)
        self.cell(0, 6, self.po_details['Supplier_address2'], ln=True)
        self.set_x(21)
        self.cell(0, 6, self.po_details['Supplier_address3'], ln=True)

        # Attn Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 64)
        self.cell(0, 6, 'Attn', ln=False)
        self.set_xy(19, 64)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.po_details['Attn'], ln=True)

        # PO Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(120, 40)
        self.cell(0, 6, 'PO No', ln=False)
        self.set_xy(120, 46)
        self.cell(0, 6, 'PO Date', ln=False)
        self.set_xy(120, 52)
        self.cell(0, 6, 'Terms', ln=False)
        self.set_xy(120, 58)
        self.cell(0, 6, 'Currency', ln=False)
        self.set_xy(120, 64)
        self.cell(0, 6, 'Ref', ln=False)

        # PO Values
        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 40)
        self.cell(0, 6, self.po_details['PO_no'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 46)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 46)
        self.cell(0, 6, self.po_details['PO_Date'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 52)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 52)
        self.cell(0, 6, self.po_details['Payment_Terms'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 58)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 58)
        self.cell(0, 6, self.po_details['Currency'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 64)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 64)
        self.cell(0, 6, self.po_details['Quote_Ref'], ln=True)
        self.line(2, 70, 207, 70)  # Line from x=10 to x=200 at y=40

        # Delivery Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 70)
        self.cell(0, 6, 'Delivery', ln=False)
        self.set_xy(19, 70)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.po_details['Delivery'], ln=True)

        # Delivery Address
        self.set_xy(21, 76)
        self.cell(0, 6, self.po_details['Address_Line1'], ln=True)
        self.set_xy(21, 82)
        self.cell(0, 6, self.po_details['Address_Line2'], ln=True)

        # Contact Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 70)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(120, 70)
        self.cell(0, 6, 'Lead Time', ln=False)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 76)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(120, 76)
        self.cell(0, 6, 'Contact', ln=False)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 82)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(120, 82)
        self.cell(0, 6, 'Phone No', ln=False)

        self.set_font("helvetica", "B", 10)
        self.set_xy(138, 88)
        self.cell(0, 6, ':', ln=False)
        self.set_xy(120, 88)
        self.cell(0, 6, 'Page', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(140) # You'll need to fine-tune this X position based on your layout
        self.cell(0, 6, f"{self.page_no()} of {{nb}}", 0, 1, 'L') # Using {nb} for total pages

        # Delivery Values
        self.set_font("helvetica", "", 10)
        self.set_xy(140, 70)
        self.cell(0, 6, self.po_details['leat_time'], ln=True)
        self.set_xy(140, 76)
        self.cell(0, 6, self.po_details['created_by'], ln=True)
        self.set_xy(140, 82)
        self.cell(0, 6, str(self.po_details['phone_number']), ln=True)
        # self.set_xy(140, 88)
        # self.cell(0, 6, '1 of 1', ln=True)

        self.line(2, 94, 207, 94)  # Line from x=10 to x=200 at y=40


        # Column widths
        item_width = 10
        part_no_width = 35
        description_width = 85
        uom_width = 15
        qty_width = 20
        unit_price_width = 25
        total_price_width = 30
        # Item table heading
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 95)
        self.cell(item_width, 6, 'S/N', ln=False)
        # self.line(5 + item_width, 94, 5 + item_width, 265)  # Vertical line

        self.set_xy(25, 95)
        self.cell(part_no_width, 6, 'Part No', ln=False)
        # self.line(15 + part_no_width, 94, 15 + part_no_width, 265)  # Vertical line

        self.set_xy(75, 95)
        self.cell(description_width, 6, 'Description', ln=False)
        # self.line(49 + description_width, 94, 49 + description_width, 265)  # Vertical line

        self.set_xy(132, 95)
        self.cell(uom_width, 6, 'UOM', ln=False)
        # self.line(135 + uom_width, 94, 135 + uom_width, 265)  # Vertical line

        self.set_xy(148, 95)
        self.cell(qty_width, 6, 'Qty', ln=False)
        # self.line(140 + qty_width, 94, 140 + qty_width, 265)  # Vertical line

        self.set_xy(161, 95)
        self.cell(unit_price_width, 6, 'Unit Price', ln=False)
        # self.line(160 + unit_price_width, 94, 160 + unit_price_width, 265)  # Vertical line

        self.set_xy(183, 95)
        self.cell(total_price_width, 6, 'Total Price', ln=False)
        # Optionally add a line at the end if desired
        # self.line(190 + total_price_width, 94, 190 + total_price_width, 265)  # Vertical line 230

        
        self.line(2, 102, 207, 102)  # Line from x=10 to x=200 at y=40
        # self.line(5, 230, 210, 230) # items table  end line 

        self.set_xy(157, 230)
        # self.cell(total_price_width, 6, 'Total (SGD)', ln=False)
        self.set_xy(157, 236)
        # self.cell(total_price_width, 6, 'GST (9%)', ln=False)
        self.set_xy(157, 242)
        # self.cell(total_price_width, 6, 'Total (SGD)', ln=False)

    def footer(self):
        if self.get_y() < 290:  # Check if we're far enough from the page bottom
            self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
            self.set_font("helvetica", "B", 10)
            self.set_font("helvetica", "B", 10)
            self.set_xy(2, 231)
            self.line(2, 285, 207, 285) # footer above line

            self.set_xy(20, 285)
            self.cell(0, 6, 'Acknowledged & Accepted By', ln=False)

            self.set_xy(140, 285)
            self.cell(0, 6, 'for Centroid Engineering Solutions', ln=False)

            self.set_xy(60, 289)
            self.cell(0, 6, 'This is a system generated PO no signature is required.', ln=False)

    def body(self):
        self.ln(10)  # space before content
        top_margin = 105  # your desired Y start position
        self.set_y(top_margin)

        # Define column widths
        item_width = 10
        part_no_width = 35
        description_width = 85
        uom_width = 15
        qty_width = 20
        unit_price_width = 25
        total_price_width = 30

        max_y = 285
        footer_space = 45

        for idx, item in enumerate(self.data_dict):
            calculated_heights = self._calculate_row_heights(item, part_no_width, description_width)
            part_no_height = calculated_heights['part_no_height']
            description_height = calculated_heights['description_height']
            row_height = max(6, part_no_height, description_height)

            current_y = self.get_y()
            remaining_space = max_y - current_y
            is_last_item = (idx == len(self.data_dict) - 1)
            # Condition 1: Not last item, and current row doesn't fit → new page
            if not is_last_item and remaining_space < row_height:
                self._draw_vertical_lines_and_add_page( item_width, part_no_width, description_width,
                    uom_width, qty_width, unit_price_width, total_price_width, top_margin)

            # Condition 2: Last item, but not enough space for row + footer → new page
            elif is_last_item and remaining_space < row_height + footer_space:
                self._draw_vertical_lines_and_add_page( item_width, part_no_width, description_width,
                    uom_width, qty_width, unit_price_width, total_price_width, top_margin)

            # Draw row
            current_y = self.get_y()

            # Render description
            self._render_description(item, description_width, current_y, item_width, part_no_width)

            # Render UOM, Qty, Unit Price, Total aligned to row height
            self._render_other_fields(item, current_y, item_width, part_no_width, description_width,
                                    uom_width, qty_width, unit_price_width, total_price_width)
            # Advance Y
            self.set_y(current_y + row_height)

        # At the end, draw footer (on last page)
        if self.get_y() + footer_space <= max_y:
            # Enough space for footer
            self._draw_final_lines_and_totals(item_width, part_no_width, description_width,
                                            uom_width, qty_width, unit_price_width, total_price_width)
        
        else:
            # Add new page for footer
            self.add_page()
            self.header()
            self.set_y(top_margin)
            self._draw_final_lines_and_totals(item_width, part_no_width, description_width,
                                            uom_width, qty_width, unit_price_width, total_price_width)

    def _calculate_row_heights(self, item, part_no_width, description_width):
        """Calculate the required heights for part number and description before rendering"""
        
        # Calculate part number height
        part_no_text = item['Part_No']
        part_no_lines = len(part_no_text.split('\n'))
        if len(part_no_text) > 0:
            # Estimate wrapped lines
            estimated_part_no_lines = max(1, int(self.get_string_width(part_no_text) / (part_no_width - 2)) + 1)
            part_no_height = max(part_no_lines, estimated_part_no_lines) * 6
        else:
            part_no_height = 6
        
        # Calculate description height more accurately
        description_text = item['item']
        description_height = self._calculate_description_height(description_text, description_width)
        
        return {
            'part_no_height': part_no_height,
            'description_height': description_height
        }

    def _calculate_description_height(self, description_text, description_width):
        """Calculate description height considering different font sizes and formatting"""
        
        lines = description_text.split('\n')
        total_height = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                total_height += 6  # Empty line height
                continue
                
            # Determine font size based on line type
            if line.startswith("Header -"):
                content = line.replace("Header -", "").strip()
                font_size = 11
            elif line.startswith("Subheader -"):
                content = line.replace("Subheader -", "").strip()
                font_size = 9
            elif line.startswith("Body -"):
                content = line.replace("Body -", "").strip()
                font_size = 10
            else:
                content = line
                font_size = 10
            
            # Set font temporarily to calculate width
            self.set_font("helvetica", "", font_size)
            
            # Calculate how many lines this content will wrap to
            if content:
                content_width = self.get_string_width(content)
                available_width = description_width - 2  # Account for margins
                lines_needed = max(1, int(content_width / available_width) + 1)
                total_height += lines_needed * 6
            else:
                total_height += 6
        
        return max(6, total_height)

    def _draw_vertical_lines_and_add_page(self, item_width, part_no_width, description_width,
                                        uom_width, qty_width, unit_price_width, total_price_width,top_margin):
        """Draw vertical lines and add a new page"""
        
        # Draw vertical lines for current page
        self.line(2 + item_width, 94, 2 + item_width, 285)
        self.line(12 + part_no_width, 94, 12 + part_no_width, 285)
        self.line(46 + description_width, 94, 46 + description_width, 285)
        self.line(132 + uom_width, 94, 132 + uom_width, 285)
        self.line(137 + qty_width, 94, 137 + qty_width, 285)
        self.line(157 + unit_price_width, 94, 157 + unit_price_width, 285)
        self.line(187 + total_price_width, 94, 187 + total_price_width, 285)
        
        # Add new page
        self.add_page()
        self.header()
        self.set_y(105)
        print(".........._draw_vertical_lines_and_add_page.......self.get_y()........",self.get_y() )

    def _render_description(self, item, description_width, current_y, item_width, part_no_width):
        """Render description with proper formatting"""
        
        description_x = 2 + item_width + part_no_width
        description_y = current_y
        
        lines = item['item'].split('\n')
        
        self.set_xy(description_x, description_y)
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("Header -"):
                content = line.replace("Header -", "").strip()
                self.set_font("helvetica", "B", 11)
            elif line.startswith("Subheader -"):
                content = line.replace("Subheader -", "").strip()
                self.set_font("helvetica", "B", 9)
            elif line.startswith("Body -"):
                content = line.replace("Body -", "").strip()
                self.set_font("helvetica", "", 10)
            else:
                content = line
                self.set_font("helvetica", "", 10)
            
            if content:
                self.set_x(description_x)
                self.multi_cell(description_width, 6, content, 0, 'L')

    def _render_other_fields(self, item, current_y, item_width, part_no_width,
                            description_width, uom_width, qty_width,
                            unit_price_width, total_price_width):
        """Render Index, Part No, UOM, Quantity, Unit Price, and Total aligned to current_y"""

        self.set_font("helvetica", "", 10)

        # --- Index (S/N)
        self.set_xy(4, current_y)
        self.cell(item_width, 6, item.get('index', ''), 0, 0)

        # --- Part No
        self.set_xy(12, current_y)
        part_no_text = item.get('Part_No', '')
        self.multi_cell(part_no_width, 6, part_no_text, 0, 'L')

        # --- UOM
        x_uom = 2 + item_width + part_no_width + description_width
        self.set_xy(x_uom, current_y)
        self.cell(uom_width, 6, item.get('uom', ''), 0, 0, 'C')

        # --- Quantity (right-aligned)
        x_qty = x_uom + uom_width
        self.set_xy(x_qty, current_y)
        qty_value = item.get('quantity', '')
        self.cell(qty_width - 10, 6, str(qty_value), 0, 0, 'R')

        # --- Unit Price (right-aligned)
        x_unit = x_qty + qty_width
        self.set_xy(x_unit, current_y)
        unit_value = item.get('Unit_Price', '')
        if unit_value is None or str(unit_value).strip().lower() == "none":
            unit_to_render = ""
        else:
            unit_to_render = str(unit_value)
        self.cell(unit_price_width - 10, 6, unit_to_render, 0, 0, 'R')

        # --- Total Price (right-aligned)
        x_total = x_unit + unit_price_width
        self.set_xy(x_total, current_y)
        total_value = item.get('total', '')
        if total_value is None or str(total_value).strip().lower() == "none":
            total_to_render = ""
        else:
            total_to_render = str(total_value)
        self.cell(total_price_width - 15, 6, total_to_render, 0, 0, 'R')

    def _draw_final_lines_and_totals(self, item_width, part_no_width, description_width,
                                uom_width, qty_width, unit_price_width, total_price_width):
        """Draw final lines and render totals section"""
        
        # Draw vertical lines
        self.line(2 + item_width, 94, 2 + item_width, 230)
        self.line(12 + part_no_width, 94, 12 + part_no_width, 230)
        self.line(46 + description_width, 94, 46 + description_width, 230)
        self.line(132 + uom_width, 94, 132 + uom_width, 254)
        self.line(137 + qty_width, 94, 137 + qty_width, 230)
        self.line(157 + unit_price_width, 94, 157 + unit_price_width, 254)
        self.line(187 + total_price_width, 94, 187 + total_price_width, 230)
        
        # Horizontal lines
        self.line(2, 230, 207, 230)
        self.line(147, 236, 207, 236)
        self.line(147, 242, 207, 242)
        self.line(147, 248, 207, 248)
        self.line(147, 254, 207, 254)
        
        # Totals labels
        self.set_xy(150, 230)
        self.set_font("helvetica", "B", 10)
        self.cell(total_price_width, 6, f"Discount ({self.po_details['Discount']})%", ln=False)
        self.set_xy(150, 236)
        self.cell(total_price_width, 6, f"Total ({self.po_details['Currency']})", ln=False)
        self.set_xy(150, 242)
        self.cell(total_price_width, 6, f"GST ({int(float(self.gst))}%)", ln=False)
        self.set_xy(150, 248)
        self.cell(total_price_width, 6, f"Grand Total ({self.po_details['Currency']})", ln=False)
        
        # Totals values
        self.set_font("helvetica", "", 10) 

        self.set_xy(182, 230)
        self.cell(total_price_width - 5, 6, self.discount_value_str, ln=False, align='R')

        self.set_xy(182, 236)
        self.cell(total_price_width - 5, 6, self.total_sum_str, ln=False, align='R')

        self.set_xy(182, 242)
        self.cell(total_price_width - 5, 6, self.gst_amount_str, ln=False, align='R')

        self.set_xy(182, 248)
        self.cell(total_price_width - 5, 6, self.final_total_str, ln=False, align='R')


        
        # Comments
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 230)
        self.cell(0, 6, 'Comments: ', ln=False)
        
        self.set_xy(25, 230)
        self.set_font("helvetica", "", 10)
        max_width = 110
        self.multi_cell(max_width, 6, self.po_details['comments'])
        
        # Footer text
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 265)
        self.cell(0, 6, 'The invoice shall be by Email to : finance@centroides.com together with the relevant supporting documents', ln=False)
        self.set_xy(2, 269)
        self.cell(0, 6, 'such as Delivery Order / Service Reports. Etc ', ln=False)

@app.route('/edit_po', defaults={'po_no': None}, methods=["POST", "GET"])
@app.route('/edit_po/<po_no>')
def edit_po(po_no):
    db = get_database()
    cursor = db.cursor()
    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])


    if request.method == 'POST':
        existing_po = request.form.get('existing_po')
        cursor.execute("SELECT id FROM created_po WHERE PO_no = ?", (existing_po,))
        result = cursor.fetchone()

        if result:
            po_id = result[0]
            update_fields = {}
            update_fields['Supplier_Name'] = request.form.get('Supplier_Name')
            update_fields['Attn'] = request.form.get('Attn')
            update_fields['phone_number'] = request.form.get('phone_number')

            from datetime import datetime
            raw_date = request.form.get('PO_Date')
            if raw_date:
                try:
                    formatted_date = datetime.strptime(raw_date, "%Y-%m-%d").strftime("%d-%m-%y")
                    update_fields['PO_Date'] = formatted_date
                except ValueError:
                    print("Invalid date format received:", raw_date)
                    update_fields['PO_Date'] = None
            else:
                update_fields['PO_Date'] = None


            update_fields['created_by'] = request.form.get('Contact')
            update_fields['Quote_Ref'] = request.form.get('Quote_Ref')
            update_fields['Expenses'] = request.form.get('code_number')
            update_fields['Delivery'] = request.form.get('Delivery')
            update_fields['Address_Line1'] = request.form.get('Address_Line1')
            update_fields['Address_Line2'] = request.form.get('Address_Line2')
            update_fields['Payment_Terms'] = request.form.get('Payment_Terms', '').upper() or None
            update_fields['Currency'] = request.form.get('Currency', '').upper() or None
            update_fields['Exchange_rate'] = request.form.get('Exchange_rate')
            update_fields['Discount'] = float(request.form.get('Discount') or 0)
            lead_time_value = request.form.get('leat_time', '').strip()
            unit_value = request.form.get('Unit', '').strip()
            update_fields['leat_time'] = (request.form.get('leat_time') or '') + ' ' + (request.form.get('Unit') or '')
            update_fields['comments'] = request.form.get('comments')

            part_nos = request.form.getlist('part_no[]')
            description_headers = request.form.getlist('description_header[]')
            description_subheaders = request.form.getlist('description_subheader[]')
            description_bodys = request.form.getlist('description_body[]')
            uoms = request.form.getlist('uom[]')
            excepted_dates = request.form.getlist('excepted_date[]') 
            quantities = request.form.getlist('quantity[]')
            unit_prices = request.form.getlist('unit_price[]')
            gst_option = request.form.get('gst_option')

            # current_date = datetime.now()
            existing_po = existing_po.strip()
            pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
            match = pattern.match(existing_po)
            if match:
                base_po_number = match.group(1)
                suffix = match.group(3)
                if suffix:
                    new_suffix = int(suffix) + 1
                else:
                    new_suffix = 1
                New_PO_no = f"{base_po_number}({new_suffix})"
            else:
                # If the PR number format is incorrect
                New_PO_no = "Invalid PO number format"

            update_fields['PO_no'] = New_PO_no

            Supplier_Name = update_fields['Supplier_Name']
            cursor.execute('''SELECT billing_address1, billing_address2, city, postcode, country, company_name 
                            FROM vendors_details WHERE display_name = ?''', (Supplier_Name,))
            vendor_data = cursor.fetchone()
            if vendor_data:
                update_fields['Supplier_address1'] = vendor_data[0]
                update_fields['Supplier_address2'] = vendor_data[1]
                update_fields['Supplier_address3'] = f"{vendor_data[4]}, {vendor_data[2]} - {vendor_data[3]}"
                update_fields['Company_name'] = vendor_data[5]

            # Dynamically build query
            set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
            values = list(update_fields.values())
            values.append(po_id)

            update_query = f"UPDATE created_po SET {set_clause} WHERE id = ?"
            cursor.execute(update_query, values)

            po_data = cursor.execute('SELECT * FROM created_po WHERE id = ?', (po_id,)).fetchone()
            if po_data:
                columns = [desc[0] for desc in cursor.description]

            else:
                print("Error: Existing PO not found in created_po table.")
                # Optionally handle it: flash message, redirect, or return an error

            cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
            latest_gst = cursor.fetchone()  # Fetch the first result
            latest_gst_value = latest_gst[0] if latest_gst else 1 
            items = []
            for idx, (part_no, uom, excepted_date, quantity, unit_price) in enumerate(zip(part_nos, uoms, excepted_dates, quantities, unit_prices)):
                # Prepare multi-line description
                lines = []
                if idx < len(description_headers) and description_headers[idx].strip():
                    lines.append(f"Header - {description_headers[idx].strip()}")
                if idx < len(description_subheaders) and description_subheaders[idx].strip():
                    lines.append(f"Subheader - {description_subheaders[idx].strip()}")
                if idx < len(description_bodys) and description_bodys[idx].strip():
                    lines.append(f"Body - {description_bodys[idx].strip()}")
                
                description = "\n".join(lines)
                total = float(quantity) * float(unit_price)
                rounded_total = round(total, 2)

                item = { 'project_id': po_data['project_id'], 'PO_number': New_PO_no, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 
                        'unit_price': float(unit_price), 'total': rounded_total, 'excepted_date': excepted_date,
                }

                item['gst'] = latest_gst_value if gst_option == 'Yes' else 1
                items.append(item)

            if items:
                for item in items:
                    cursor.execute("""INSERT INTO po_items ( project_id, PO_number, Part_No,item,  quantity,  uom,  Unit_Price, GST,  total, excepted_date, status)  
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                        (item['project_id'],item['PO_number'],item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'],
                            item['gst'], item['total'], item['excepted_date'], 'Open' ))


                cursor.execute('DELETE FROM po_items WHERE PO_number = ?', (existing_po,))
                db.commit()


        return redirect(url_for('pur_po'))       
            



    created_po = db.execute("SELECT * FROM created_po WHERE PO_no = ?", (po_no,)).fetchall()
    created_po = [dict(row) for row in created_po]
    po_items = db.execute("SELECT * FROM po_items WHERE PO_number = ?", (po_no,)).fetchall()
    po_items = [dict(row) for row in po_items]
    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]

    user_access = get_employee_access_control(user['name'])
    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])

    return render_template( 'admin_templates/purchase/prpoedit.html', created_po=created_po, Supplier_Names=Supplier_Names, usernames=usernames,
                          user_access=user_access, department_code=department_code,user=user,po_items=po_items,gst=gst)

@app.route('/prpoedit', defaults={'id': None}, methods=["POST", "GET"])
@app.route('/prpoedit/<int:id>', methods=["POST", "GET"])
@login_required
def prpoedit(id):

    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    # Accessing the query parameter 'p'
    p = request.args.get('p', default=None, type=int)

    if p == 1:

        if request.method == 'POST':

            action = request.form.get('action')

            if action == 'update_header':
                project_id = request.form.get('project_id', type=int)
                Supplier_Name = request.form.get('Supplier_Name')
                # Query to fetch the details from vendors_details table based on the Supplier_Name
                query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
                cursor.execute(query, (Supplier_Name,))
                result = cursor.fetchone()

                if result:
                    Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
                    Supplier_address3 = f"{country}, {city} - {postcode}"

                Attn = request.form.get('Attn')
                leat_time = request.form.get('leat_time')
                Contact = request.form.get('Contact')
                phone_number = request.form.get('number')
                PR_Date = request.form.get('PR_Date') 
                Old_PR_no = request.form.get('Old_PR_no')
                New_PR_no = request.form.get('New_PR_no')

                parts = Old_PR_no.split('-')
                if len(parts) == 3:
                    project_id1 = parts[0]
                    serial_number1 = parts[2]
                cursor.execute("SELECT id FROM created_pr where PR_no = ?", (Old_PR_no,))
                header_id = cursor.fetchone()[0]  
                Quote_Ref = request.form.get('Quote_Ref')


                comments = request.form.get('comments')
                Delivery = request.form.get('Delivery')
                Address_Line1 = request.form.get('Address_Line1')
                Address_Line2 = request.form.get('Address_Line2')
                Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
                Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
                db = get_database()
                cursor = db.cursor()


                # **Rename PR Quote File**
                upload_dir = 'docment_data/PR Quotes'
                old_file_path = os.path.join(upload_dir, f"{Old_PR_no}.*")  # Any file with Old_PR_no as prefix

                # Get the actual file extension
                for file in os.listdir(upload_dir):
                    if file.startswith(Old_PR_no):
                        old_filename = file
                        file_extension = os.path.splitext(file)[1]  # Get the extension
                        new_filename = f"{New_PR_no}{file_extension}"
                        new_file_path = os.path.join(upload_dir, new_filename)

                        # Rename the file
                        os.rename(os.path.join(upload_dir, old_filename), new_file_path)
                        print(f"File renamed from {old_filename} to {new_filename}")
                        break  # Stop after renaming the first matching file


                # Update the created_pr table with updated header details
                cursor.execute(''' UPDATE created_pr SET PR_no = ?, Supplier_Name = ?, Attn = ?,  phone_number = ?, PR_Date = ?, Quote_Ref = ?,  Delivery = ?, Address_Line1 = ?,  Address_Line2 = ?,  Payment_Terms = ?, 
                        Currency = ?, comments = ?,  Supplier_address1 = ?,  Supplier_address2 = ?,  Supplier_address3 = ?,  Company_name = ?,  leat_time = ?, created_by=? WHERE id = ? ''', 
                        ( New_PR_no, Supplier_Name, Attn, phone_number, PR_Date, Quote_Ref, Delivery,  Address_Line1, Address_Line2,  Payment_Terms, 
                        Currency, comments,  Supplier_address1, Supplier_address2, Supplier_address3,  Company_name,  leat_time, Contact, header_id ))
                
                cursor.execute(''' UPDATE pr_items SET pr_number = ? WHERE pr_number = ? ''', (New_PR_no, Old_PR_no))
                db.commit()

                return redirect(url_for('pur_purchase'))

            if action == 'update_pr':

                project_id = request.form.get('project_id')
                pr_number = request.form.get('PR_no')
                New_PR_no  = request.form.get('New_PR_no')
                gst_checkbox = request.form.get('gstCheckbox')
                part_nos = request.form.getlist('part_no[]')
                descriptions = request.form.getlist('description[]')
                uoms = request.form.getlist('uom[]')
                quantities = request.form.getlist('quantity[]')
                unit_prices = request.form.getlist('unit_price[]')
                items = []
                cursor.execute("DELETE FROM pr_items WHERE pr_number = ?", (pr_number,))

                for part_no, description, uom, quantity, unit_price in zip(part_nos, descriptions, uoms, quantities, unit_prices):
                    total = float(quantity) * float(unit_price)
                    rounded_total = round(total, 2) 
                    item = { 'project_id': project_id,'pr_number': New_PR_no, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 'unit_price': float(unit_price), 'total': rounded_total }
                    if gst_checkbox:
                        cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
                        latest_gst = cursor.fetchone()  # Fetch the first result
                        latest_gst_value = latest_gst[0] if latest_gst else 1  
                        item['gst'] = latest_gst_value
                        # print("......item['gst']....",item['gst'])
                    else:
                        item['gst'] = 1
                    items.append(item)

                if items:

                    for item in items:
                        cursor.execute("""INSERT INTO pr_items (project_id, pr_number, Part_No, item, quantity, uom, Unit_Price, GST, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                                    (item['project_id'], item['pr_number'], item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'], item['gst'], item['total']))
                    db.commit()  
                    # Update the status of the PR
                    # status = 'Approved' if department_code <= 1001 else 'Created'
                    # cursor.execute("UPDATE created_pr SET status = ? WHERE PR_no = ?", (status, pr_number))
                    from datetime import datetime
                    current_date = datetime.now()
                    formatted_date = current_date.strftime("%d-%m-%y")
                    cursor.execute('''UPDATE created_pr SET PR_no = ?, PR_Date = ?  WHERE PR_no = ?''',  (New_PR_no, formatted_date, pr_number))
                    db.commit()
                
                else:
                    cursor.execute("DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?", (pr_number, project_id))
                    db.commit()

                db.commit()
                return redirect(url_for('pur_purchase'))



        cursor.execute('SELECT display_name FROM vendors_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

        cursor.execute('SELECT username FROM admin_user')
        usernames = sorted([row[0] for row in cursor.fetchall()])

        cursor.execute("SELECT * FROM created_pr where id = ?", (id,))
        header_details = cursor.fetchone() 

        cursor.execute("SELECT PR_no FROM created_pr where id = ?", (id,))
        prnumber = cursor.fetchone()[0]  

        # Fetch pr_items associated with pr_number
        cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (prnumber,))
        pr_items = cursor.fetchall()
        parts = prnumber.split('-')
        if len(parts) == 3:
            project_id = parts[0]

        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d-%m-%y")

        # pattern = re.compile(r"(\d{4}-\d{4}-\d{4}|\d{4}-\d{3}-\d{4})(\((\d+)\))?$")
        pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
        match = pattern.match(prnumber)
        if match:
            base_pr_number = match.group(1)
            suffix = match.group(3)
            if suffix:
                new_suffix = int(suffix) + 1
            else:
                new_suffix = 1
            New_PR_no = f"{base_pr_number}({new_suffix})"
        else:
            # If the PR number format is incorrect
            New_PR_no = prnumber
            
        show = 'pr'
        p =1
        user_access = get_employee_access_control(user['name'])

        return render_template('admin_templates/purchase/prpoedit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                           user_access=user_access,show =show, New_PR_no=New_PR_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

    if p == 2:

        if request.method == 'POST':

            action = request.form.get('action')

            if action == 'update_header':
                project_id = request.form.get('project_id', type=int)
                Supplier_Name = request.form.get('Supplier_Name')
                # Query to fetch the details from vendors_details table based on the Supplier_Name
                query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
                cursor.execute(query, (Supplier_Name,))
                result = cursor.fetchone()

                if result:
                    Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
                    Supplier_address3 = f"{country}, {city} - {postcode}"

                Attn = request.form.get('Attn')
                leat_time = request.form.get('leat_time')
                Contact = request.form.get('Contact')
                phone_number = request.form.get('number')
                PO_Date = request.form.get('PO_Date') 
                Old_PO_no = request.form.get('Old_PO_no')
                New_PO_no = request.form.get('New_PO_no')

                parts = Old_PO_no.split('-')
                if len(parts) == 3:
                    project_id1 = parts[0]
                    serial_number1 = parts[2]
                cursor.execute("SELECT id FROM created_po where PO_no = ?", (Old_PO_no,))
                header_id = cursor.fetchone()[0]  
                Quote_Ref = request.form.get('Quote_Ref')


                comments = request.form.get('comments')
                Delivery = request.form.get('Delivery')
                Address_Line1 = request.form.get('Address_Line1')
                Address_Line2 = request.form.get('Address_Line2')
                Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
                Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
                # Update the created_pr table with updated header details
                db = get_database()
                cursor = db.cursor()
                cursor.execute(''' UPDATE created_po SET PO_no = ?, Supplier_Name = ?, Attn = ?,  phone_number = ?, PO_Date = ?, Quote_Ref = ?,  Delivery = ?, Address_Line1 = ?,  Address_Line2 = ?,  Payment_Terms = ?, 
                        Currency = ?, comments = ?,  Supplier_address1 = ?,  Supplier_address2 = ?,  Supplier_address3 = ?,  Company_name = ?,  leat_time = ?, created_by=?, status = ?, PO_Issued_by = ? WHERE id = ? ''', 
                        ( New_PO_no, Supplier_Name, Attn, phone_number, PO_Date, Quote_Ref, Delivery,  Address_Line1, Address_Line2,  Payment_Terms, 
                        Currency, comments,  Supplier_address1, Supplier_address2, Supplier_address3,  Company_name,  leat_time, Contact, 'Reissued', user['name'], header_id ))
                
                cursor.execute(''' UPDATE po_items SET PO_number = ? WHERE PO_number = ? ''', (New_PO_no, Old_PO_no))
                cursor.execute(''' UPDATE manual_entry  SET cost_center_id  = ? WHERE cost_center_id = ? ''', (New_PO_no, Old_PO_no))
                db.commit()
 

                user_access = get_employee_access_control(user['name'])

                return redirect(url_for('pur_po'))



            if action == 'update_po':

                project_id = request.form.get('project_id')
                PO_number = request.form.get('PO_no')
                New_PO_no  = request.form.get('New_PO_no')
                # print(".....first...New_PO_no.........",New_PO_no)
                gst_checkbox = request.form.get('gstCheckbox')
                part_nos = request.form.getlist('part_no[]')
                descriptions = request.form.getlist('description[]')
                uoms = request.form.getlist('uom[]')
                quantities = request.form.getlist('quantity[]')
                unit_prices = request.form.getlist('unit_price[]')
                items = []
                cursor.execute("DELETE FROM po_items WHERE PO_number = ?", (PO_number,))
                cursor.execute("DELETE FROM manual_entry WHERE cost_center_id = ?", (PO_number,))

                for part_no, description, uom, quantity, unit_price in zip(part_nos, descriptions, uoms, quantities, unit_prices):


                    quantity = quantity if quantity else '0'
                    unit_price = unit_price if unit_price else '0'
                    
                    try:
                        total = float(quantity) * float(unit_price)
                        rounded_total = round(total, 2)
                    except ValueError:
                        total = 0
                        rounded_total = 0
                    item = { 'project_id': project_id,'PO_number': New_PO_no, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 'unit_price': float(unit_price), 'total': rounded_total }
                    if gst_checkbox:

                        cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
                        latest_gst = cursor.fetchone() 
                        latest_gst_value = latest_gst[0] if latest_gst else 1  
                        item['gst'] = latest_gst_value
                    else:
                        item['gst'] = 1
                    items.append(item)

                if items:

                    for item in items:
                        cursor.execute("""INSERT INTO po_items (project_id, PO_number, Part_No, item, quantity, uom, Unit_Price, GST, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                                    (item['project_id'], item['PO_number'], item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'], item['gst'], item['total']))
                        total_sum = float(item['total'])
                        cost = item['quantity'] * item['unit_price']

                        parts = New_PO_no.split('-')
                        if len(parts) == 3:
                            Expenses = parts[1]
                        cursor.execute("INSERT INTO manual_entry (project_id, username, department_code, cost, gst_value, total, cost_center_id) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                    (project_id, user['name'], Expenses, cost , item['gst'], total_sum,New_PO_no ))
                    from datetime import datetime
                    current_date = datetime.now()
                    formatted_date = current_date.strftime("%d-%m-%y")
                    cursor.execute('''UPDATE created_po SET PO_no = ?, PO_Date = ?  WHERE PO_no = ?''',  (New_PO_no, formatted_date, PO_number))
                    cursor.execute('''UPDATE created_po SET status = ? WHERE PO_no = ?''',  ('Reissued',New_PO_no))
                    db.commit()
                
                else:
                    cursor.execute("DELETE FROM created_po WHERE PO_no = ? AND project_id = ?", (PO_number, project_id))
                    db.commit()


                cursor.execute('SELECT PR_no FROM created_pr')
                pr_nos = cursor.fetchall()

                # Iterate through each PR_no and check for corresponding items in pr_items
                for pr_no in pr_nos:
                    cursor.execute('SELECT COUNT(*) FROM pr_items WHERE pr_number = ? ', (pr_no[0],))
                    count = cursor.fetchone()[0]
                    if count == 0 and header_true == 0:
                        cursor.execute('DELETE FROM created_pr WHERE PR_no = ? ', (pr_no[0],))


                user_access = get_employee_access_control(user['name'])

                return redirect(url_for('pur_po'))

        cursor.execute('SELECT display_name FROM vendors_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

        cursor.execute('SELECT username FROM admin_user')
        usernames = sorted([row[0] for row in cursor.fetchall()])
        
        cursor.execute("SELECT * FROM created_po where id = ?", (id,))
        header_details = cursor.fetchone() 
        cursor.execute("SELECT PO_no FROM created_po WHERE id = ?", (id,))
        result = cursor.fetchone()

        if result is not None:
            ponumber = result[0]
        else:
            # Handle the case where no rows were returned
            ponumber = None
        # Fetch pr_items associated with pr_number
        cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (ponumber,))
        pr_items = cursor.fetchall()
        # parts = ponumber.split('-')
        if ponumber:
            parts = ponumber.split('-')
        else:
            # Handle the case where ponumber is None
            parts = []
        
        if len(parts) == 3:
            project_id = parts[0]
        
        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d-%m-%y")
        ponumber = ponumber.strip()
        # pattern = re.compile(r"(\d{4}-\d{4}-\d{4}|\d{4}-\d{3}-\d{4})(\((\d+)\))?$")
        pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
        match = pattern.match(ponumber)
        if match:
            base_pr_number = match.group(1)
            
            suffix = match.group(3)
            if suffix:
                new_suffix = int(suffix) + 1
            else:
                new_suffix = 1
            New_PO_no = f"{base_pr_number}({new_suffix})"
        else:
            # If the PR number format is incorrect
            New_PO_no = "Invalid PR number format"
        show = 'po'
        user_access = get_employee_access_control(user['name'])

        return render_template('admin_templates/purchase/prpoedit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                          user_access=user_access,show = show, New_PO_no=New_PO_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def PR_Created_Notification(employee_emails, project_name, project_id, created_by, pr_number):
    sender_email = "cestimesheet67@gmail.com"
    sender_password = "rmlomkpnujzzvlsy"  # It's recommended to use environment variables or a secure config

    subject = f"CES-PR-{project_id}"
    body = (
        f"Dear Sir/Madam,\n\n"
        f"This is to inform you that a new Purchase Requisition (PR) has been created for Project '{project_name}' (ID: {project_id}).\n\n"
        f"PR Number: {pr_number}\n"
        f"Created by: {created_by}\n\n"
        "We kindly request your approval for the PR at your earliest convenience.\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    server = None  # Initialize server to ensure it's defined
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = ", ".join(employee_emails)
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        server.sendmail(sender_email, employee_emails, message.as_string())
        print(f"PR approval email sent successfully to: {', '.join(employee_emails)}")

    except Exception as e:
        print(f"Error sending email: {e}")

    finally:
        if server:
            server.quit()

def PR_Approval_Notification(all_emails, pr_date, project_id, approved_by, created_by, PR_no):
    sender_email = "cestimesheet67@gmail.com"
    sender_password = "rmlomkpnujzzvlsy"  # Direct password (not recommended for security)

    subject = f"CES-PR- {project_id}"
    body = (
        # "Test mail please ignore.\n\n"
        f"Dear {created_by},\n\n"
        f"We are pleased to inform you that the Purchase Requisition (PR) you requested for Project ID {project_id} on {pr_date} has been approved by {approved_by}.\n\n"
        f"PR Number: {PR_no}\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )
    server = None
    try:
        # Establish connection with SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Upgrade connection to secure
        server.login(sender_email, sender_password)  # Login with secure credentials

        # Construct the email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = ", ".join(all_emails)  # Send to multiple recipients
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Send the email
        server.sendmail(sender_email, all_emails, message.as_string())
        print(f"PR approval email sent successfully to: {', '.join(all_emails)}")

    except Exception as e:
        print(f"Error sending email: {e}")

    finally:
        if server:
            server.quit()  # Close SMTP connection

def PR_Issued_Notification(mail_to_list, project_name, project_id, created_by, pr_number):
    # Establish connection with SMTP server
    sender_email = "cestimesheet67@gmail.com"
    sender_password = "rmlomkpnujzzvlsy"  # Direct password (not recommended for security)

    # Set subject and email body
    subject = f"CES-PR-{project_id}"
    body = (
        # "Test mail please ignore.\n\n"
        f"Dear Sir/Madam,\n\n"
        f"This is to inform you that a new Purchase Request (PR) has been Requested to Process for Project '{project_name}' (ID: {project_id}).\n\n"
        f"PR Number: {pr_number}\n"
        f"Created and Approved by: {created_by}\n\n"
        "We kindly request your approval for the PO at your earliest convenience.\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )
    server = None

    try:
        # Establish connection with SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Upgrade connection to secure
        server.login(sender_email, sender_password)  # Login with secure credentials

        # Construct the email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = ", ".join(mail_to_list)  # Send to multiple recipients
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Send the email
        server.sendmail(sender_email, mail_to_list, message.as_string())
        print(f"PR approval email sent successfully to: {', '.join(mail_to_list)}")

    except Exception as e:
        print(f"Error sending email: {e}")

    finally:
        if server:
            server.quit()  # Close SMTP connection

def PR_Processed_Notification(mail_to_list,PR_no,project_id,issued_by,PO_no):
    sender_email = "cestimesheet67@gmail.com"
    sender_password = "rmlomkpnujzzvlsy"  # Direct password (not recommended for security)
    # Set subject and email body
    subject = f"CES-PO-{project_id}"
    body = (
        # "Test mail please ignore.\n\n"
        f"Dear Sir/Madam,\n\n"
        f"Your requested Purchase Request (PR) {PR_no} for Project ID {project_id} has been issued by {issued_by} as PO number {PO_no}.\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )
    server = None
    try:
        # Establish connection with SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Upgrade connection to secure
        server.login(sender_email, sender_password)  # Login with secure credentials

        # Construct the email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = ", ".join(mail_to_list)  # Send to multiple recipients
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Send the email
        server.sendmail(sender_email, mail_to_list, message.as_string())
        print(f"PR approval email sent successfully to: {', '.join(mail_to_list)}")

    except Exception as e:
        print(f"Error sending email: {e}")

    finally:
        if server:
            server.quit()  # Close SMTP connection

@app.route('/pur_poupdate',methods=['GET', 'POST'])
@login_required
def pur_poupdate():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    db = get_database()  
    cursor = db.cursor()

    user_access = get_employee_access_control(user['name'])
    cursor.execute('SELECT PO_no FROM created_po ORDER BY id DESC')
    PO_Numbers = [row[0] for row in cursor.fetchall()]
    return render_template('admin_templates/purchase/pur_poupdate.html',user_access=user_access,department_code=department_code,user=user,PO_Numbers=PO_Numbers)

@app.route('/fetch_poupdate_details', methods=['POST'])
def fetch_poupdate_details():
    data = request.get_json()
    po_number = data.get('po_number')
    db = get_database()

    # Query `po_items` for the selected PO number, selecting all columns with `*`
    cursor = db.execute(""" SELECT * FROM po_items WHERE PO_number = ? """, (po_number,))
    po_items = cursor.fetchall()

    # Query `Material_Receipt` for received quantities per item
    received_data = {}
    cursor_received = db.execute(""" SELECT item_name, SUM(quantity) as received_qty FROM Material_Receipt WHERE po_number = ? GROUP BY item_name """, (po_number,))

    for row in cursor_received.fetchall():
        received_data[row['item_name']] = row['received_qty']
    
    # Combine PO item data with received quantity data
    items = []
    for item in po_items:
        item_dict = dict(item)  # Convert each row to a dictionary for easy modification
        item_dict['received_qty'] = received_data.get(item['item'], 0)  # Add received_qty from Material_Receipt
        items.append(item_dict)

        # Query `created_po` to get the PO_Date for the given po_number
    cursor_po = db.execute("SELECT PO_Date FROM created_po WHERE PO_no = ?", (po_number,))
    created_po = cursor_po.fetchone()
    po_date = created_po['PO_Date'] if created_po else None  # Handle case if PO number is not found


    print("......items.................", items)
    print("......po_date.................",po_date)
    return jsonify({ 'po_date': po_date, 'items': items})

@app.route('/update_po_update', methods=['POST'])
def update_material_receipt():
    data = request.get_json()
    po_number = data.get('po_number')
    items = data.get('items')

    if not po_number or not items:
        return jsonify({"success": False, "error": "Missing data"})

    db = get_database()
    for item in items:
        db.execute("""
            UPDATE po_items
            SET excepted_date = ?
            WHERE id = ? AND PO_number = ?
        """, (item['received_date'], item['id'], po_number))
    db.commit()

    return jsonify({"success": True})

##--------------------------------------------------------ADMIN------------------------------------------------------------------------------------------------------------------

@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))
    is_pm = is_pm_for_project(user['name'])

    total_projects_query = 'SELECT COUNT(*) FROM projects'
    total_projects = db.execute(total_projects_query).fetchone()[0]

    total_eq_query = 'SELECT COUNT(*) FROM enquiries'
    total_eqs = db.execute(total_eq_query).fetchone()[0]

    leaves_on_current_day_query = """SELECT COUNT(DISTINCT employeeID) AS number_of_employees FROM leaves WHERE STRFTIME('%Y-%m-%d', leave_date) = DATE('now')"""
    leaves_on_current_day = db.execute(leaves_on_current_day_query).fetchone()[0]

    total_users_query = 'SELECT COUNT(*) FROM admin_user'
    total_users = db.execute(total_users_query).fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM client_details")
    client_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vendors_details")
    vendor_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM created_pr")
    pr_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM created_po")
    po_count = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(total_cost) FROM workingHours")
    total_cost = cursor.fetchone()[0]

    summary_data = {
        'total_projects': total_projects,
        'total_eqs': total_eqs,
        'leaves_on_current_day': leaves_on_current_day,
        'total_users': total_users,
        'client_count': client_count,
        'vendor_count': vendor_count,
        'pr_count': pr_count,
        'po_count': po_count,
        'total_cost': total_cost
    }


    cursor.execute("SELECT COUNT(*) FROM claims WHERE status = 'Paid'")
    approved_claims = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM claims WHERE status != 'Paid'")
    open_claims = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM claims")
    total_claims = cursor.fetchone()[0]

    # Payment Request counts
    cursor.execute("SELECT COUNT(*) FROM payment_request WHERE status = 'Paid'")
    paid_payments = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM payment_request WHERE status = 'Pending'")
    pending_payments = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM payment_request")
    total_payments = cursor.fetchone()[0]


    # Payment Request counts
    cursor.execute("SELECT COUNT(*) FROM Expenses WHERE status = 'Approved'")
    paid_expenses = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Expenses WHERE status != 'Approved'")
    pending_expenses = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM Expenses")
    total_expenses = cursor.fetchone()[0]


    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status = 'Processed'")
    paid_pr = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed'")
    pending_pr = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_pr")
    total_pr = cursor.fetchone()[0]


    cursor.execute("SELECT COUNT(*) FROM created_po WHERE status IN ('Closed' );")
    paid_po = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_po WHERE status NOT IN ('Closed');")
    pending_po = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_po")
    total_po = cursor.fetchone()[0]


    cursor.execute("SELECT COUNT(*) FROM leaves_approved WHERE status = 'Approved'")
    paid_leaves = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM leaves_approved WHERE status != 'Approved'")
    pending_leaves = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM leaves_approved")
    total_leaves = cursor.fetchone()[0]


    cursor.execute("SELECT COUNT(*) FROM projects_request WHERE approved_status != 'Created'")
    prj_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM projects_request WHERE approved_status = 'Created'")
    prj_created = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM projects_request")
    total_prj = cursor.fetchone()[0]

    status_counts = {
        'claims': {
            'approved_claims': approved_claims,
            'open_claims': open_claims,
            'total_claims': total_claims
        },
        'projects_request': {
            'prj_pending': prj_pending,
            'prj_created': prj_created,
            'total_prj': total_prj
        },
        'payment_requests': {
            'paid_payments': paid_payments,
            'pending_payments': pending_payments,
            'total_payments': total_payments
        },
        'expenses':{
            'paid_expenses': paid_expenses,
            'pending_expenses': pending_expenses,
            'total_expenses':total_expenses
        },
        'pr':{
            'paid_pr':paid_pr,
            'pending_pr': pending_pr,
            'total_pr':total_pr 
        },
        'po':{
            'paid_po':paid_po,
            'pending_po': pending_po,
            'total_po':total_po
        },
        'leaves' : {
            'paid_leaves' : paid_leaves,
            'pending_leaves': pending_leaves,
            'total_leaves' : total_leaves
        }
    }

    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/admin/index.html',user=user,department_code=department_code,is_pm=is_pm, user_access=user_access,
                           summary_data=summary_data,status_counts=status_counts)

@app.route('/admin_add_project', methods=["POST", "GET"])
@login_required
def admin_add_project():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    active_tab = 'add_new'
    user = get_current_user()
    db = get_database() 
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    from datetime import datetime

    if department_code != 1000:
        return redirect(url_for('login'))

    if request.method == "POST":
        projectId = request.form['projectid']
        client = request.form['client']
        projectName = request.form['projectname']
        startTime = request.form['start_time']
        endTime = request.form['end_time']
        status = request.form['status']
        po_number = request.form['po_number']
        po_value = request.form['po_value']
        pm = request.form['projectmanager']
        pe = request.form['projectengneer']
        budget = request.form['budget']
        billing_address =request.form['billing_address']
        delivery_address = request.form['delivery_address']
        type = request.form['type']
        selected_members = request.form.get('selected_members', '')
        db = get_database()

        try:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM projects WHERE id = ?', (projectId,))
            result = cursor.fetchone()

            if result:
                flash(f"  already exists!.", 'add_project_error')
            else:
                db.execute('INSERT INTO projects (id, client, project_name, start_time, end_time, pm_status, pe_status, status, po_number, pm, pe, po_value, budget, billing_address, delivery_address, type, project_members) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           [projectId, client, projectName, startTime, endTime, 1, 1, status, po_number, pm, pe, po_value, budget, billing_address, delivery_address, type, selected_members])
                db.commit()
                flash(f" {projectId} is successfully added.", 'add_project')

            show = 'Project'

        except sqlite3.IntegrityError:
            flash(f"Project ID ' {projectId} ' already exists. Please provide a unique ID.", 'error')

    user_access = get_employee_access_control(user['name'])
    user = get_current_user()
    db = get_database() 
    cursor = db.cursor()

    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    pmlist1 = [row[0] for row in cursor.fetchall()]
    pmlist = sorted(pmlist1, key=lambda x: x.lower())

    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    teamlist1 = [row[0] for row in cursor.fetchall()]
    teamlist = sorted(teamlist1, key=lambda x: x.lower())

    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    message = ''  # Initialize an empty message
    cursor.execute('SELECT EnquiryNumber FROM enquiries WHERE EnquiryNumber NOT IN (SELECT id FROM projects) ORDER BY EnquiryNumber DESC')
    project_ids = [row[0] for row in cursor.fetchall()]
    cursor = db.execute('SELECT * FROM cost_center ORDER BY id DESC')
    cost_center = cursor.fetchall()
    cursor = db.execute('SELECT * FROM industry ORDER BY id DESC')
    industry_list = cursor.fetchall()
    cursor = db.execute('SELECT * FROM vehicle ORDER BY id DESC')
    Vehicle_list = cursor.fetchall()
    current_year = datetime.now().year

    cursor.execute('SELECT * FROM GST ')
    gst_data = cursor.fetchall()
    show = 'Project'
    latest_date = max(row['date'] for row in gst_data) if gst_data else None  # Adjust 'date' to the correct column name
    cursor.execute("SELECT * FROM overhead_budget")
    oh_budget = cursor.fetchall()
    cursor = db.execute('SELECT * FROM bank_details ORDER BY id DESC')
    bank_details = cursor.fetchall()
    cursor = db.execute('SELECT * FROM Accommodation ORDER BY id DESC')
    Accommodation_details = cursor.fetchall()

    cursor.execute("SELECT type, type_values FROM expenses_values")
    rows = cursor.fetchall()

    cursor = db.execute('SELECT * FROM expenses_values ORDER BY id DESC')
    expense_types = cursor.fetchall()

 
    print(".expense_types_dict.............",expense_types)
    return render_template('admin_templates/admin/admin_add_project.html',project_ids=project_ids, user=user,cost_center=cost_center, usernames=usernames, 
                           latest_date=latest_date,gst_data=gst_data, pmlist=pmlist,teamlist=teamlist,Accommodation_details=Accommodation_details,
                            show=show,department_code=department_code,user_access=user_access, bank_details=bank_details,
                           oh_budget=oh_budget,Vehicle_list=Vehicle_list,industry_list=industry_list,message=message,expense_types=expense_types)

@app.route('/admin_add_employee', methods=["POST", "GET"])
@login_required
def admin_add_employee():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    show = None
    department_code = get_department_code_by_username(user['name'])
    from datetime import datetime

    if department_code != 1000:
        return redirect(url_for('login'))

    if request.method == "POST":
        button_value = request.form.get('submit')
        Delete_Course = request.form.get('Delete_Course')
        Delete_industry = request.form.get('Delete_industry')
        Delete_Vehicle = request.form.get('Delete_Vehicle')
        Delete_gst = request.form.get('Delete_gst')
        Delete_bank = request.form.get('Delete_bank')


        if button_value == 'add_gst':
            date = request.form['date']
            GST = request.form['GST']
            check_query = 'SELECT COUNT(*) FROM GST WHERE date = ? AND GST = ? '
            cursor.execute(check_query, ( date, GST))
            result = cursor.fetchone()
            
            if result[0] > 0:
                flash(f'Same GST already exists in this {date}!', 'GST_update1')
            else:
                insert_query = '''INSERT INTO GST (date, GST) VALUES (?, ?)'''
                cursor.execute(insert_query, (date,GST))
                flash(f'{GST} % GST has been added successfully! on {date}', 'GST_update')
                db.commit()
            show = 'GST'

        if Delete_Course:
            cursor.execute('DELETE FROM cost_center WHERE id = ?', (Delete_Course,))
            flash('Code Deleted successfully!', 'code_added')
            show = 'cost_center'
            db.commit()

        if Delete_Vehicle:
            cursor.execute('DELETE FROM vehicle WHERE id = ?', (Delete_Vehicle,))
            flash('Vehicle Deleted successfully!', 'Vehicle')
            show = 'Vehicle'
            db.commit()

        if Delete_industry:
            cursor.execute('DELETE FROM industry WHERE id = ?', (Delete_industry,))
            flash('Industry Deleted successfully!', 'indusry')
            show = 'industry'
            db.commit()
        
        if Delete_gst:
            cursor.execute('DELETE FROM GST WHERE id = ?', (Delete_gst,))
            flash('GST Deleted successfully!', 'GST_update')
            show = 'GST'
            db.commit()
        
        if Delete_bank:
            cursor.execute('DELETE FROM bank_details WHERE id = ?', (Delete_bank,))
            flash('Bank details Deleted successfully!', 'bankadd')
            show = 'bank_add'
            db.commit()

        if button_value == "add_cost_center":
            expenses_code = request.form['Expenses_Code']
            expenses_name = request.form['Expenses_Name']
            pay_rate = request.form['pay_rate']
            cursor.execute('SELECT * FROM cost_center WHERE code = ?', (expenses_code,))
            existing_code = cursor.fetchone()
            if existing_code:
                flash('Code already exists!', 'code_exits')
            else:
                cursor.execute('INSERT INTO cost_center (code, expenses_name,hourly_rate) VALUES (?, ?, ?)', (expenses_code, expenses_name,pay_rate))
                flash('Code has been added successfully!', 'code_added')
                db.commit()
            show = 'cost_center'
        
        elif button_value == "add_industry":
            industry_name = request.form['Industry_Name']
            cursor.execute('SELECT * FROM industry WHERE industry = ?', (industry_name,))
            existing_industry = cursor.fetchone()

            if existing_industry:
                flash('Industry already exists!', 'indusry_exits')
            else:
                cursor.execute('INSERT INTO industry (industry) VALUES (?)', (industry_name,))
                flash('Industry has been added successfully!', 'indusry')
                db.commit()
            show = 'industry'  

        elif button_value == "add_Vehicle":
            Vehicle_Name = request.form['Vehicle_Name']
            Vehicle_Number = request.form['Vehicle_Number']
            cursor.execute('SELECT * FROM vehicle WHERE Vehicle_number = ?', (Vehicle_Number,))
            existing_vehicle = cursor.fetchone()
            if existing_vehicle:
                flash('vehicle already exists!', 'Vehicle_exits')
            else:
                cursor.execute('INSERT INTO vehicle ( Vehicle_name, Vehicle_number ) VALUES (?, ?)', (Vehicle_Name, Vehicle_Number))
                flash('vehicle has been added successfully!', 'Vehicle')
                db.commit()
            show = 'Vehicle'  
            
        elif button_value == "add_user":
            name = request.form['empname']
            username = request.form['username']
            department_code = request.form['department_code']
            register = request.form['register']
            rate_per_hour = request.form['rate_per_hour']
            cursor.execute('SELECT * FROM admin_user WHERE name = ?', (name,))
            existing_email = cursor.fetchone()
            cursor.execute('SELECT * FROM admin_user WHERE username = ?', (username,))
            existing_username = cursor.fetchone()
            show = 'adduser'
            if existing_email:
                flash('Email already exists!', 'user_add_eeror')
            elif existing_username:
                flash(f" '{username} ' already exists!", 'user_add_eeror')
            else:
                try:
                    db.execute('INSERT INTO admin_user (name, username, department_code, register, rate_per_hour) VALUES (?, ?, ?, ?, ?)',
                            (name, username, department_code, register, rate_per_hour))
                    db.commit()
                    flash(f" '{username} ' added successfully!", 'user_add')
                except sqlite3.IntegrityError:
                    error = f"Employee ID '{username}' already exists. Please provide a unique ID."

        elif button_value == "add_new_description":
            oh_Code = request.form['oh_Code']
            oh_Description = request.form['oh_Description']
            oh_Amount = request.form.get('oh_Amount', "").strip()
            if not oh_Amount:
                oh_Amount = 0.0
            else:
                oh_Amount = float(oh_Amount)

            cursor.execute('SELECT * FROM overhead_budget WHERE code = ?', (oh_Code,))
            existing_code = cursor.fetchone()
            cursor.execute('SELECT * FROM overhead_budget WHERE expenses_name = ?', (oh_Description,))
            existing_expenses = cursor.fetchone()
            show = 'OH_Budget'
            if existing_code:
                flash('Code already exists!', 'oh_budget_error')
            elif existing_expenses:
                flash(f" '{oh_Description} ' already exists!", 'oh_budget_error')
            else:
                try:
                    db.execute('INSERT INTO overhead_budget (code, expenses_name, budget) VALUES (?, ?, ?)', (oh_Code, oh_Description,oh_Amount))
                    db.commit()
                    flash(f" '{oh_Code}' with description {oh_Description} added successfully!", 'oh_budget')
                except sqlite3.IntegrityError:
                    error = f"'{oh_Description}' already exists. Please provide a unique ID."
            
        elif button_value == "bank_add":
            Bank_Name = request.form['Bank_Name']
            Account_Number = request.form['Account_Number']
            Branch = request.form['Branch']
            Swift = request.form['Swift']
            Pay_Now = request.form['Pay_Now']
            cursor.execute('SELECT * FROM bank_details WHERE Account_Number = ?', (Account_Number,))
            existing_acc_number = cursor.fetchone()
            show = 'bank_add'
            if existing_acc_number:
                flash('Account Number already exists!', 'bankexits')
            else:
                try:
                    db.execute('INSERT INTO bank_details (Bank_Name, Account_Number, Branch, Swift, Pay_Now) VALUES (?, ?, ?, ?, ?)',
                                (Bank_Name, Account_Number, Branch, Swift, Pay_Now))
                    db.commit()
                    flash(f" '{Bank_Name}' with account number {Account_Number} added successfully!", 'bankadd')
                except sqlite3.IntegrityError:
                    error = f"'{oh_Description}' already exists. Please provide a unique ID."

            
    cursor = db.execute('SELECT * FROM cost_center ORDER BY id DESC')
    cost_center = cursor.fetchall()
    cursor = db.execute('SELECT * FROM bank_details ORDER BY id DESC')
    bank_details = cursor.fetchall()
    cursor = db.execute('SELECT * FROM industry ORDER BY id DESC')
    industry_list = cursor.fetchall()
    cursor = db.execute('SELECT * FROM vehicle ORDER BY id DESC')
    Vehicle_list = cursor.fetchall()

    cursor = db.execute('SELECT * FROM Accommodation ORDER BY id DESC')
    Accommodation_details = cursor.fetchall()
    current_year = datetime.now().year
    cursor.execute('SELECT * FROM GST ')
    gst_data = cursor.fetchall()
    cursor.execute("SELECT * FROM overhead_budget")
    oh_budget = cursor.fetchall()
    latest_date = max(row['date'] for row in gst_data) if gst_data else None  # Adjust 'date' to the correct column name
    user_access = get_employee_access_control(user['name'])
    cursor = db.execute('SELECT * FROM expenses_values ORDER BY id DESC')
    expense_types = cursor.fetchall()
    return render_template('admin_templates/admin/admin_add_project.html',user_access=user_access,show=show, Vehicle_list=Vehicle_list, 
                          latest_date=latest_date,gst_data=gst_data,cost_center=cost_center,industry_list=industry_list,
                          bank_details=bank_details,oh_budget=oh_budget,user=user,department_code=department_code,
                          expense_types=expense_types,Accommodation_details=Accommodation_details)

@app.route('/update_overhead_budget', methods=['POST'])
def update_overhead_budget():
    db = get_database()
    try:
        data = request.get_json()
        budgets = data.get('budgets', {})
        for row_id, new_budget in budgets.items():
            # Update the overhead_budget table with the new budget
            db.execute('UPDATE overhead_budget SET budget = ? WHERE id = ?', (new_budget, row_id))
        db.commit()
        return jsonify({"success": True, "budgets": budgets})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

UPLOAD_FOLDER = 'C:/Users/Hewlett Packard/Desktop/do/'  # Specify the folder where you want to save the Excel files

def export_client_details():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()

    # Fetch all data from the client_details table
    query = 'SELECT * FROM vendors_details'
    df = pd.read_sql_query(query, db)

    # Close the database connection
    db.close()

    # Specify the Excel file path
    excel_path = os.path.join(UPLOAD_FOLDER, 'vendors_details_export.xlsx')

    # Create the uploads folder if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # Write the DataFrame to an Excel sheet
    df.to_excel(excel_path, index=False, engine='openpyxl')

    # Optionally, save the DataFrame to a CSV file as well
    csv_path = os.path.join(UPLOAD_FOLDER, 'vendors_details_export.csv')
    df.to_csv(csv_path, index=False)

    # Send the Excel file as a response
    return None

@app.route('/employees_view', methods=['GET', 'POST'])
@login_required
def employees_view():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
       
    if department_code != 1000:
        return redirect(url_for('login'))
    db = get_database() 
    cursor = db.cursor()
    cursor.execute("SELECT * FROM admin_user")
    admin_users = cursor.fetchall()
    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT code, expenses_name FROM cost_center ORDER BY CAST(code AS INTEGER) ASC")
    cost_centers = cursor.fetchall()  # Returns a list of tuples [(code1, name1), (code2, name2), ...]

    return render_template('admin_templates/admin/employees_view.html',user_access=user_access, user=user, admin_users=admin_users,
                           department_code=department_code,usernames = usernames,cost_centers=cost_centers)

@app.route('/edituser', methods=['POST'])
@login_required
def edituser():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    db = get_database()
    cursor = db.cursor()
    
    # Get form data
    user_id = request.form.get('id')
    name = request.form.get('name')  # Email
    username = request.form.get('username')
    rate_per_hour = request.form.get('rate_per_hour')
    department_code = request.form.get('department_code')
    register = request.form.get('register')
    primary_role = request.form.get('Primary_role')
    secondary_role = request.form.get('Secondary_role')

    Controls = {

        "10": [
            "toggleEnquiry", "toggleCreateEnquiry", "toggleEditEnquiry", "toggleDeleteEnquiry",
            "toggleProfPurchaseRequest", "togglecreate_PR_All", "togglec_PR_all_create", "toggle_PR_all_view","toggle_PR_all_approve",
            "toggleProjectRequest", "toggleprf_prj_NewRequest", "togglePendingRequest", "toggleRequestedList",
            "toggle_prof_approveprj", "toggleProfPurchaseOrder", "toggleProf_po_View_All", "togglePaymentRequest",
            "toggleView_pro_Request_view_all", "toggleView_pro_Request_Create_all", "toggle_prof_claims",
            "toggle_prof_view_all_Claims", "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewallDO",
            "toggleProjects", "toggleDashboard", "toggleAllProjects", "toggleEditPM", "toggleEditAllProjects",
            "toggleProjectStatus", "toggleAllstatusProjects", "toggleHoursEdit", "toggleHoursView", "toggleProjectDetails",
            "toggleOverview", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest", "togglePurchase",
            "togglePurchaseRequest", "toggleViewPRDetails", "toggleApproveAnyPR", "toggleIssueAnyPO", "toggleEditPR",
            "toggleDeletePR", "togglePurchaseOrder", "toggleViewPODetails", "toggleEditPO", "togglePrintPO",
            "toggleCreatePRAllProjects","toggleMaterialReceipt","toggleReceive","toggleReceiptRecords","togglePOUpdate",
            "toggleprofSuppliers" ,"toggleprofEditpurSupplier" ,"toggleprofDeletepurSupplier" ,"toggleprofAddpurSupplier",
            "toggleHrsView","toggleOverview"
        ],
        "11": [
            "toggleEnquiry", "toggleCreateEnquiry", "toggleEditEnquiry", "toggleDeleteEnquiry",
            "toggleProfPurchaseRequest", "togglecreate_PR_All", "togglec_PR_all_create", "toggle_PR_all_view","toggle_PR_all_approve",
            "toggleProjectRequest", "toggleprf_prj_NewRequest", "togglePendingRequest", "toggleRequestedList",
            "toggle_prof_approveprj", "toggleProfPurchaseOrder", "toggleProf_po_View_All", "togglePaymentRequest",
            "toggleView_pro_Request_view_all", "toggleView_pro_Request_Create_all", "toggle_prof_claims",
            "toggle_prof_view_all_Claims", "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewallDO",
            "toggleProjects", "toggleDashboard", "toggleAllProjects", "toggleEditPM", "toggleEditAllProjects",
            "toggleProjectStatus", "toggleAllstatusProjects", "toggleHoursEdit", "toggleHoursView", "toggleProjectDetails",
            "toggleOverview", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest", "togglePurchase",
            "togglePurchaseRequest", "toggleViewPRDetails", "toggleApproveAnyPR", "toggleIssueAnyPO", "toggleEditPR",
            "toggleDeletePR", "togglePurchaseOrder", "toggleViewPODetails", "togglePrintPO",
            "toggleCreatePRAllProjects","toggleMaterialReceipt","toggleReceive","toggleReceiptRecords","togglePOUpdate",
             "toggleprofSuppliers" ,"toggleprofEditpurSupplier" ,"toggleprofDeletepurSupplier" ,"toggleprofAddpurSupplier",
             "toggleHrsView","toggleOverview"
        ],

        "12": [
            "Accounts", 
            "toggleClient","toggleHrsView",
             "toggleAddClient", "toggleEditClient", "toggleDeleteClient", "toggleSuppliers",
            "toggleAddSupplier", "toggleEditSupplier", "toggleDeleteSupplier", "toggleExpenses", "toggleInvoice",
            "toggleNewInvoice", "toggleEditInvoice", "toggleDeleteInvoice", "toggleViewInvoice", "toggleOverHeadPayReq",
            "toggle_ac_overhead_pay_NewRequest", "togglePaymentRequest", "toggleView_pro_Request_view_all",
            "toggleView_pro_Request_Create_all", "toggle_prof_claims", "toggle_prof_view_all_Claims",
            "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewallDO"
        ],
        "13": [
            "toggleHR", "toggleADD", "toggleAddCourse", "toggleEditCourse", "toggleDeleteCourse", "toggleAddLeave",
            "toggleEditLeave", "toggleDeleteLeave", "toggleAddAsset", "toggleEditAsset", "toggleDeleteAsset",
            "toggleAddHoliday", "toggleEditHoliday", "toggleDeleteHoliday", "toggleHRLeaves", "toggleLeaveOverview",
            "togglePendingApprovals", "toggleApproveRejectLeave", "toggleDeleteLeavePending", "toggleLeaveStats",
            "toggleLeaveAllocation", "toggleAddLeaveAllocation", "toggleEditLeaveAllocation", "toggleDeleteLeaveAllocation",
            "toggleHRProfile", "toggleUpdateBio", "toggleUpdateCourse", "toggleUpdateAssets",
            "toggleHrsView","toggleOverview"
        ],
        "14": [
            "toggleProfPurchaseRequest", "togglecreate_PR_All", "togglec_PR_all_create", "toggle_PR_all_view","toggleDashboard",
            "toggleProfPurchaseOrder", "toggleProf_po_View_All", "togglePaymentRequest", "toggleView_pro_Request_view_all",
            "toggleView_pro_Request_Create_all", "toggle_prof_claims", "toggle_prof_view_create_Claims", "toggleProjects",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest", "togglePurchase",
            "togglePurchaseRequest", "toggleViewPRDetails", "toggleApproveAnyPR", "toggleIssueAnyPO", "toggleEditPR",
            "toggleDeletePR", "togglePurchaseOrder", "toggleViewPODetails", "toggleEditPO", "togglePrintPO",
            "toggleCreatePRAllProjects","toggleMaterialReceipt","toggleReceive","toggleReceiptRecords","togglePOUpdate",
             "toggleprofSuppliers" ,"toggleprofEditpurSupplier" ,"toggleprofDeletepurSupplier" ,"toggleprofAddpurSupplier",
             "toggleHrsView","toggleOverview"
        ],
        "15": [
            "toggleEnquiry", "toggleCreateEnquiry", "toggleEditEnquiry", "toggleHrsView",
            "toggleDeleteEnquiry", "toggleProjects", "toggle_prof_view_create_Claims",
            "togglePurchase", "togglePurchaseRequest", "toggleViewPRDetails", 
            "toggleDeletePR" ,"toggle_prof_claims","toggleCreatePRAllProjects"
        ],
        "16": [
            "toggle_prof_claims", "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleProjects","toggleDashboard",
            "toggleProjectDetails", "toggleOverview", "toggleHrsView", "toggleGeneratePR", "togglePRJViewPR",
            "toggleprjViewPO", "toggleViewClaims", "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests",
            "toggleCreatePaymentRequest", "togglePurchase", "togglePurchaseRequest", "toggleViewPRDetails",
            "toggleEditPR","toggleDeletePR", "toggleApproveAnyPR", "toggleIssueAnyPO", "togglePurchaseOrder", "toggleViewPODetails"
        ],
        "17": [
            "toggle_prof_claims", "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleProjects","toggleDashboard",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest", "togglePurchase",
            "togglePurchaseOrder", "toggleViewPODetails","toggleMaterialReceipt","toggleReceive","toggleReceiptRecords","togglePOUpdate",
             "toggleHrsView",
            
        ],
        "18": [
            "Accounts", "toggleClient", "toggleAddClient", "toggleEditClient", "toggleDeleteClient", "toggleSuppliers",
            "toggleAddSupplier", "toggleEditSupplier", "toggleDeleteSupplier", "toggleExpenses", "toggleInvoice",
            "toggleNewInvoice", "toggleEditInvoice", "toggleDeleteInvoice", "toggleViewInvoice", "toggleOverHeadPayReq",
            "toggle_ac_overhead_pay_NewRequest", "togglePaymentRequest", "toggleView_pro_Request_view_all",
            "toggleView_pro_Request_Create_all", "toggle_prof_claims", "toggle_prof_view_create_Claims",
             "toggleHrsView",
        ],
        "19": [
            "toggleProfPurchaseRequest", "togglecreate_PR_Involved", "togglec_PR_Involved_create", "toggle_PR_Involved_view",
            "toggleProf_po_View_Involved", "togglePaymentRequest", "toggleView_pro_Request_view_involved","toggleDashboard",
            "toggleView_pro_Request_Create_involved", "toggle_prof_claims", "toggle_prof_view_involved_Claims",
            "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewinvolvedDO", "toggleProjects",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest",
             "toggleHrsView"
        ],

        "1001": [
            "toggleProfPurchaseRequest", "togglecreate_PR_Involved", "togglec_PR_Involved_create", "toggle_PR_Involved_view",
            "toggle_PR_Involved_approve", "toggleProjectRequest", "toggleprf_prj_NewRequest", "togglePendingRequest",
            "toggleRequestedList", "toggleProf_po_View_Involved", "togglePaymentRequest","toggleDashboard",
            "toggleView_pro_Request_view_involved", "toggleView_pro_Request_Create_involved", "toggle_prof_claims",
            "toggle_prof_view_involved_Claims", "toggle_prof_view_create_Claims", "toggleDeliveryOrders",
            "toggleViewinvolvedDO", "toggleProjects", "toggleProjectDetails", "toggleOverview", "toggleHrsView",
            "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims", "togglePrjViewDO",
            "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest","toggleEditPM",
            "toggleOverview"
        ],
        "1002": [
            "toggleProfPurchaseRequest", "togglecreate_PR_Involved", "togglec_PR_Involved_create", "toggle_PR_Involved_view",
            "toggleProf_po_View_Involved", "togglePaymentRequest", "toggleView_pro_Request_view_involved",
            "toggleView_pro_Request_Create_involved", "toggle_prof_claims", "toggle_prof_view_involved_Claims",
            "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewinvolvedDO", "toggleProjects",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims", "toggleHrsView",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest","toggleDashboard"
        ],
        "1003": [
            "toggleProfPurchaseRequest", "togglecreate_PR_Involved", "togglec_PR_Involved_create", "toggle_PR_Involved_view",
            "toggleProf_po_View_Involved", "togglePaymentRequest", "toggleView_pro_Request_view_involved",
            "toggleView_pro_Request_Create_involved", "toggle_prof_claims", "toggle_prof_view_involved_Claims",
            "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewinvolvedDO", "toggleProjects",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims", "toggleHrsView",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest","toggleDashboard"
        ],
        "1004": [
            "toggleProfPurchaseRequest", "togglecreate_PR_Involved", "togglec_PR_Involved_create", "toggle_PR_Involved_view",
            "toggleProf_po_View_Involved", "togglePaymentRequest", "toggleView_pro_Request_view_involved","toggleDashboard",
            "toggleView_pro_Request_Create_involved", "toggle_prof_claims", "toggle_prof_view_involved_Claims",
            "toggle_prof_view_create_Claims", "toggleDeliveryOrders", "toggleViewinvolvedDO", "toggleProjects", "toggleHrsView",
            "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO", "toggleViewClaims",
            "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest"
        ],
        "1005": [
            "toggleProjects", "toggleProjectDetails", "toggleGeneratePR", "togglePRJViewPR", "toggleprjViewPO","toggleDashboard",
            "toggleViewClaims", "toggleHrsView", "togglePrjViewDO", "toggleCreateDO", "togglePaymentRequests", "toggleCreatePaymentRequest"
        ],
        "None" : [
        "toggleProfile", "toggleAccountHub", "togglePersonalDetails", "toggleprof_Leaves", "toggle_prof_Courses",
        "toggle_prof_Payslip", "toggle_prof_Assets", "toggle_prof_TimeSheet", "toggle_prof_Project",
        "toggle_prof_Estimation", "toggle_prof_Overhead", "toggle_prof_Service", "toggle_prof_Warranty",
        "togglePlanner", "toggleResources"
        ]
    }



        
        # Extract role codes (assuming format: "code|name")
        
    primary_role_code, primary_role_name = (primary_role.split('|') if primary_role else ('', ''))
    secondary_role_code, secondary_role_name = (secondary_role.split('|') if secondary_role else ('', ''))

    primary_controls = Controls.get(primary_role_code, [])
    secondary_controls = Controls.get(secondary_role_code, [])
    all_controls = list(set(primary_controls + secondary_controls))

    default_controls = {
        "toggleProfile", "toggleAccountHub", "togglePersonalDetails", "toggleprof_Leaves", "toggle_prof_Courses",
        "toggle_prof_Payslip", "toggle_prof_Assets", "toggle_prof_TimeSheet", "toggle_prof_Project",
        "toggle_prof_Estimation", "toggle_prof_Overhead", "toggle_prof_Service", "toggle_prof_Warranty",
        "togglePlanner", "toggleResources"
    }

    # Append the default controls if they are not already in all_controls
    for control in default_controls:
        if control not in all_controls:
            all_controls.append(control)
    
    if user_id:  # Update existing employee
        cursor.execute("""
            UPDATE admin_user
            SET name = ?, username = ?, rate_per_hour = ?, department_code = ?,
                register = ?, primary_role = ?, secondary_role = ?, secondary_role_code = ?
            WHERE id = ?
        """, (name, username, rate_per_hour, primary_role_code, register,
              primary_role_name, secondary_role_name, secondary_role_code, user_id))
        
    else:  # Insert new employee
        cursor.execute("""
            INSERT INTO admin_user (name, username, rate_per_hour, department_code,
                                    register, primary_role, secondary_role, secondary_role_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, username, rate_per_hour, primary_role_code, register,
              primary_role_name, secondary_role_name, secondary_role_code))

        user_id = cursor.lastrowid #get the last inserted row id.

    control_values = {}  # A dictionary to hold the toggle values for each control
    # Dynamically add the controls to the SQL query and set 'On' for all controls that need to be updated
    for control in all_controls:
        control_values[control] = 'On'  # Set the value to 'On' for these controls

    cursor.execute("SELECT 1 FROM access_control WHERE Employee_ID = ?", (username,))
    row = cursor.fetchone()

    if row:
        cursor.execute("DELETE FROM access_control WHERE Employee_ID = ?", (username,))
        db.commit()  # Commit the deletion

    # Prepare the data for insertion
    columns = ["Employee_ID"] + list(control_values.keys())  # Add the column names to be inserted
    values = [username] + list(control_values.values())  # Add the username and values for the controls

    # SQL INSERT query
    sql_query = f""" INSERT INTO access_control ({', '.join(columns)}) VALUES ({', '.join(['?'] * len(values))}) """
    cursor.execute(sql_query, values)
    db.commit()  # Commit the insertion

    return redirect(url_for('employees_view'))
  
@app.route('/admin_leaves', methods=["POST", "GET"])
@login_required
def admin_leaves():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    from datetime import datetime
    department_code = get_department_code_by_username( user['name'])
    if department_code != 1000:
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))  # Redirect to a safe page, like the home page
    # Continue with admin page logic
    db = get_database() 
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY EmployeeID COLLATE NOCASE')
    leaves_data = cursor.fetchall()
    current_year = datetime.now().year
    cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
    holidays_data = cursor.fetchall()
    public_holidays_count = len(holidays_data)
    
    show = 'add_leave'

    if 'add_or_save' in request.form:
        EmployeeID = request.form['employee_id']
        Medical = request.form['Medical']
        Casual = request.form['Casual']
        Annual = request.form['Annual']
        Maternity = request.form['Maternity']
        Paternity = request.form['Paternity']
        Year = request.form['Year']
        Start_Date = request.form['Start_Date']
        cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
        existing_data = cursor.fetchone()
        cursor.execute('SELECT COUNT(*) FROM public_holidays')
        holiday_count = cursor.fetchone()[0]

        if existing_data:
            update_query = ''' UPDATE admin_leave_allocation SET Medical = ?, Casual = ?, Annual = ?, Maternity = ?, Paternity = ?, Public=?, Year=?, Start_Date=?  WHERE EmployeeID = ?'''
            db.execute(update_query, (Medical, Casual, Annual, Maternity, Paternity,holiday_count,Year, Start_Date, EmployeeID))
            flash(f" Leaves for '{EmployeeID}' updated successfully!.", 'update_leaves')
        else:
            insert_query = '''INSERT INTO admin_leave_allocation (EmployeeID, Medical, Casual, Annual, Maternity, Paternity, Public, Year, Start_Date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'''
            db.execute(insert_query, (EmployeeID, Medical, Casual, Annual, Maternity, Paternity, holiday_count, Year, Start_Date))
            flash(f" Leaves for '{EmployeeID}' added successfully!.", 'update_leaves')
        db.commit()

        cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY EmployeeID COLLATE NOCASE')
        leaves_data = cursor.fetchall()
        user_access = get_employee_access_control(user['name'])
        show = 'add_leave'
        # return render_template('admin_templates/admin/admin_leaves.html',user_access=user_access, user=user, usernames=usernames,leaves_data=leaves_data,
        #                        department_code=department_code,holidays_data=holidays_data)
    
    elif 'add_date' in request.form:
        date = request.form['date']
        # Description = request.form['Description']
        insert_query = '''INSERT INTO public_holidays (date) VALUES (?)'''
        db.execute(insert_query, (date,))
        cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
        # Fetch the data
        holidays_data = cursor.fetchall()
        current_year = datetime.now().year
        # Modify the query to filter data for the current year
        cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
        # Fetch the data
        holidays_data = cursor.fetchall()
        public_holidays_count = len(holidays_data)
        cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (public_holidays_count,))
        cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY EmployeeID COLLATE NOCASE')
        leaves_data = cursor.fetchall()
        db.commit()
        user_access = get_employee_access_control(user['name'])
        return render_template('admin_templates/admin/admin_leaves.html', user_access=user_access,user=user, usernames=usernames,leaves_data=leaves_data,
                               department_code=department_code,holidays_data=holidays_data)
    
    elif 'get_data' in request.form:

        EmployeeID = request.form['employee_id1']
        leave_types = ['Medical', 'Casual', 'Annual', 'Maternity', 'Paternity']
        # Initialize eligibility_dict with leave types and zero values
        eligibility_dict = {leave_type: 0 for leave_type in leave_types}
        # Retrieve data from the database
        cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
        employee_leave_eligibility_data = cursor.fetchall()

        # Update eligibility_dict based on the retrieved data
        for row in employee_leave_eligibility_data:
            row_dict = dict(row)
            # for key, value in row_dict.items():
                # print(f"{key}: {value}")
            for leave_type in leave_types:
                leave_value = row_dict.get(leave_type, 0) 

                if isinstance(leave_value, (int, float)):
                    eligibility_dict[leave_type] += int(leave_value)
                elif isinstance(leave_value, str) and leave_value.strip():
                    try:
                        eligibility_dict[leave_type] += int(leave_value)
                    except ValueError:
                        print(f"Invalid value for {leave_type}: {leave_value}")
                else:
                    print(f"Empty or non-string value for {leave_type}")

        cursor.execute('''SELECT leave_type, COUNT(*) AS total_days_used FROM leaves WHERE employeeID = ? GROUP BY leave_type''', (EmployeeID,))
        employee_leave_used_data = cursor.fetchall()

        used_dict = {row['leave_type']: row['total_days_used'] for row in employee_leave_used_data}
        if 'Medical' in used_dict:
            used_dict['Medical'] = used_dict.pop('Medical')
        
        table_rows = []
        # Iterate through leave types and populate the table
        for leave_type in eligibility_dict:
            eligibility = eligibility_dict.get(leave_type, 0)
            used = used_dict.get(leave_type, 0)
            left = eligibility - used
            # Append a tuple representing a table row
            table_rows.append((leave_type, eligibility, used, left))
        table_rows = [(leave_type.replace('Medical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]

        user_access = get_employee_access_control(user['name'])
        # return render_template('admin_templates/admin/admin_leaves.html', user_access=user_access,user=user, usernames=usernames,leaves_data=leaves_data,
        #                        department_code=department_code,holidays_data=holidays_data,table_rows=table_rows,EmployeeID=EmployeeID)
    
    user_access = get_employee_access_control(user['name'])
    #-------------------------------------------------------------------------------------------------------------------------------------

    # Dictionary to store the results
    leave_data = {}

    # Fetch data from admin_leave_allocation
    cursor.execute("SELECT id, EmployeeID, Medical, Casual, Annual, Maternity, Paternity, Year, Start_Date FROM admin_leave_allocation")
    employees = cursor.fetchall()

    # Fetch leave days used from leaves table and store in dictionary
    cursor.execute("SELECT employeeID, leave_type, COUNT(*) AS days_used FROM leaves WHERE status = 'Approved' GROUP BY employeeID, leave_type")
    used_leaves = cursor.fetchall()
    # print("........used_leaves.....",used_leaves)

    # Create a dictionary for used days by employee and leave type
    used_days = {}
    for row in used_leaves:
        print("......row......",row)
        employee_id = row[0]
        leave_type = row[1]
        days_used = row[2]
        if employee_id not in used_days:
            used_days[employee_id] = {}
        used_days[employee_id][leave_type] = days_used

    # print("......used_days........",used_days)

    # Calculate pro-rated and total leave information for each employee
    for emp in employees:
        employee_id = emp[1]
        start_date = emp[8]
        days_since_joined = calculate_days_since_joined(start_date)

        leave_info = {
            "Medical": {"days eligible": emp[2] or 0},
            "Casual": {"days eligible": emp[3] or 0},
            "Annual": {"days eligible": emp[4] or 0},
            "Maternity": {"days eligible": emp[5] or 0},
            "Paternity": {"days eligible": emp[6] or 0},
        }

        # Calculate pro-rated leave and days used
        for leave_type, info in leave_info.items():
            eligibility = info["days eligible"]
            pro_rate = calculate_pro_rated_leave(days_since_joined, eligibility)
            days_used = used_days.get(employee_id, {}).get(leave_type, 0)
            days_left = eligibility - days_used

            # Populate the dictionary with calculated values
            info["pro_rate"] = round(pro_rate, 2)
            info["days used"] = days_used
            info["days left"] = round(days_left, 2)

        # Store this employee's leave data in the main dictionary
        leave_data[employee_id] = leave_info

    # Print the leave data for each employee (or process further as needed)

    #----------------------------------------------------------------------------------------------------
    
    
    cursor.execute(""" SELECT employeeID, leave_type, leave_date, approved_by, approved_date  FROM leaves  WHERE status = 'Approved'  """)
    leaves = cursor.fetchall()

    leave_data = defaultdict(lambda: defaultdict(list))  # Group data by employeeID and leave type
    days_used = defaultdict(lambda: defaultdict(int))  # Days used per leave type for each employee
    monthly_leave_counts = defaultdict(lambda: defaultdict(int))  # Monthly leave count per employee
    leave_type_counts = defaultdict(lambda: defaultdict(int))  # Leave type count for each employee

    for leave in leaves:
        employeeID = leave['employeeID']
        leave_type = leave['leave_type'] 
        
        # Format dates
        leave_date = datetime.strptime(leave['leave_date'], '%Y-%m-%d')
        leave_month = leave_date.strftime('%B')  # Get month name for monthly chart
        leave_date_formatted = leave_date.strftime('%d/%m/%y')
        approved_date = (datetime.strptime(leave['approved_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['approved_date'] else 'N/A')

        leave_entry = { 
            'leave_date': leave_date_formatted,
            'approved_by': leave['approved_by'],
            'approved_date': approved_date
        }

        leave_data[employeeID][leave_type].append(leave_entry)
        days_used[employeeID][leave_type] += 1
        monthly_leave_counts[employeeID][leave_month] += 1
        leave_type_counts[employeeID][leave_type] += 1

    # Ensure all months are represented in the chart data with 0 if no leaves
    all_months = [month for month in calendar.month_name if month]  # List of all month names (excluding empty string)
    for employeeID in monthly_leave_counts:
        monthly_leave_counts[employeeID] = {month: monthly_leave_counts[employeeID].get(month, 0) for month in all_months}

    # Fetch leave allocation for all employees
    cursor.execute("""  SELECT EmployeeID, Medical, Casual, Annual, Maternity, Paternity, Public, Unpaid FROM admin_leave_allocation WHERE Year = ? """, (datetime.now().year,))
    allocations = cursor.fetchall()

    allocations_dict = {allocation['EmployeeID']: allocation for allocation in allocations}

    chart_data = defaultdict(dict)
    for employeeID in leave_data:
        # Leave allocation for the current employee
        allocation = allocations_dict.get(employeeID, {"Medical": 0, "Casual": 0, "Annual": 0, "Maternity": 0, "Paternity": 0, "Public": 0, "Unpaid": 0})

        chart_data[employeeID] = { 
            "leave_types": ["Medical", "Casual", "Annual", "Maternity", "Paternity", "Public", "Unpaid"],
            "eligible_days": [
                allocation["Medical"], allocation["Casual"], allocation["Annual"], 
                allocation["Maternity"], allocation["Paternity"], allocation["Public"], allocation["Unpaid"]
            ],
            "days_used": [
                days_used[employeeID].get("Medical", 0), days_used[employeeID].get("Casual", 0), days_used[employeeID].get("Annual", 0),
                days_used[employeeID].get("Maternity", 0), days_used[employeeID].get("Paternity", 0), days_used[employeeID].get("Public", 0), 
                days_used[employeeID].get("Unpaid", 0)
            ],
            "months": list(monthly_leave_counts[employeeID].keys()),
            "monthly_leave_counts": list(monthly_leave_counts[employeeID].values()),
            "leave_counts": list(leave_type_counts[employeeID].values())
        }

    # Fetch additional approved leaves data from 'leaves_approved' table for all employees
    cursor.execute(""" 
        SELECT employeeID, leave_type, start_date, end_date, number_of_days, status, approved_by, approved_date 
        FROM leaves_approved 
        ORDER BY start_date DESC 
    """)
    approved_leaves = cursor.fetchall()

    approved_leaves_data = defaultdict(list)
    for leave in approved_leaves:
        employeeID = leave['employeeID']
        approved_leaves_data[employeeID].append({
            "leave_type": leave['leave_type'],
            "start_date": datetime.strptime(leave['start_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['start_date'] else 'N/A',
            "end_date": datetime.strptime(leave['end_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['end_date'] else 'N/A',
            "number_of_days": int(''.join(filter(str.isdigit, leave['number_of_days']))),
            "status": leave['status'],
            "approved_by": leave['approved_by'],
            "approved_date": datetime.strptime(leave['approved_date'], '%Y-%m-%d').strftime('%d/%m/%y') if leave['approved_date'] else 'N/A'
        })

    # Generate insights for all employees
    total_used = defaultdict(int)
    total_eligible = defaultdict(int)




    return render_template('admin_templates/admin/admin_leaves.html',user_access=user_access, user=user, usernames=usernames,leaves_data=leaves_data,
                          leave_data=leave_data, show=show,department_code=department_code,holidays_data=holidays_data)

# Function to calculate pro-rated leave
def calculate_pro_rated_leave(days_since_joined, eligibility):
    DAYS_PER_YEAR = 365
    MONTHS_PER_YEAR = 12
    return (days_since_joined / DAYS_PER_YEAR) * (eligibility / MONTHS_PER_YEAR)

@app.route('/get_enquiry_details', methods=['POST'])
@login_required
def get_enquiry_details():
    project_id = request.form.get('project_id')
    db = get_database()
    cursor = db.cursor()

    # Initialize defaults
    client = projectName = po_value = None
    billing_address1 = billing_address2_formatted = bcompany_name = None
    delivery_address1 = delivery_address_formatted = dcompany_name = None

    # Get enquiry details
    cursor.execute('SELECT Client, Name, EstimateValue FROM enquiries WHERE EnquiryNumber = ?', [project_id])
    result = cursor.fetchone()
    if result:
        client, projectName, po_value = result
        client_name = client

        # Billing address
        cursor.execute('''SELECT billing_address1, billing_address2, billing_city, billing_postcode, billing_country, company_name 
                          FROM client_details WHERE display_name = ?''', (client_name,))
        result = cursor.fetchone()
        if result:
            billing_address1, billing_address2, bcity, bpostcode, bcountry, bcompany_name = result
            billing_address2_formatted = f"{bcountry}, {bcity} - {bpostcode}"

        # Delivery address
        cursor.execute('''SELECT delivery_address1, delivery_address2, delivery_city, delivery_postcode, delivery_country, company_name 
                          FROM client_details WHERE display_name = ?''', (client_name,))
        result = cursor.fetchone()
        if result:
            delivery_address1, delivery_address2, dcity, dpostcode, dcountry, dcompany_name = result
            delivery_address_formatted = f"{dcountry}, {dcity} - {dpostcode}"

    return jsonify({
        'client': client,
        'projectName': projectName,
        'po_value': po_value,
        'bcompany_name': bcompany_name,
        'billing_address1': billing_address1,
        'billing_address2': billing_address2_formatted,
        'dcompany_name': dcompany_name,
        'delivery_address1': delivery_address1,
        'delivery_address2': delivery_address_formatted
    })

@app.route('/deleteuser/<int:userid>', methods = ["GET", "POST"])
@login_required
def deleteuser(userid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        dbuser_cur = db.execute('SELECT username FROM admin_user WHERE id = ?', [userid,])
        existing_username = dbuser_cur.fetchone()[0]
        db.execute('DELETE FROM admin_user WHERE id = ?', (userid,))
        db.execute('delete from users where name = ?', (existing_username,))
        db.commit()
        return redirect(url_for('employees_view'))
    return render_template('employees_view.html', user = user)

@app.route('/admin_claims', methods=["POST", "GET"])
@login_required
def admin_claims():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))


    all_claims_cur = db.execute("SELECT * FROM claims WHERE claim_id NOT LIKE 'E%' ORDER BY id DESC;")
    all_claims = [dict(row) for row in all_claims_cur.fetchall()]
    user_access = get_employee_access_control(user['name'])
    from datetime import datetime
    return render_template('admin_templates/admin/admin_claims.html',all_claims=all_claims,user_access=user_access, 
                            user = user,department_code=department_code,now=datetime.now)

@app.route('/admin_update_claim', methods=['POST'])
def admin_update_claim():
    db = get_database()
    data = request.get_json()

    claim_id = data['claim_id']
    paid_amt = float(data['paid_amt'])
    actual_req_amt = float(data['actual_req_amt'])
    comments = data['comments']
    cursor = db.cursor()
    user = get_current_user()

    cursor.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
    claim_details = cursor.fetchone()

    result = cursor.execute("SELECT * FROM claimed_items WHERE claim_no = ?", (claim_id,))
    items = result.fetchall()

    if not claim_details or not items:
        return jsonify({'success': False, 'error': 'Claim ID not found or no items in claim.'})

    try:
        cursor.execute("SELECT 1 FROM manual_entry WHERE cost_center_id = ? LIMIT 1", (claim_id,))
        already_exists = cursor.fetchone()

        if not already_exists:
            for item in items:
                db.execute(""" INSERT INTO manual_entry (username, project_id, department_code, cost, gst_value, total, cost_center_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?) """, ( claim_details['claim_by'], item['projectid'], 0, item['amount'], 
                                                       item['gst_value'], item['total'], item['claim_no'] ))

        if paid_amt == actual_req_amt:
            balance = 0
            status = "Paid"
        else:
            balance = actual_req_amt - paid_amt
            status = "Partial"

        from datetime import datetime

        approved_date = datetime.now().strftime("%Y-%m-%d")  # Format: YYYY-MM-DD
        approved_by = user['name']

        db.execute("""
            UPDATE claims
            SET balance = ?, comments = ?, status = ?, approved_date = ?, approved_by = ?
            WHERE claim_id = ?
        """, (balance, comments, status, approved_date, approved_by, claim_id))
        db.commit()



        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    
        formattted_actual_req_amt = locale.format_string('%.2f', actual_req_amt, grouping=True)
        formattted_paid_amt = locale.format_string('%.2f', paid_amt, grouping=True)
        formattted_balance = locale.format_string('%.2f', balance, grouping=True)

        # Fetch the email (username) from the query
        user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (claim_details['claim_by'],))
        mail_to_row = user_cur.fetchone()

        if mail_to_row:
            employee_email = mail_to_row[0]  # Get the email

            import re
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            if re.match(email_regex, employee_email):
                # Send the notification
                print("claim approved")
                Claim_approval_Notification(employee_email, claim_details['claim_by'], claim_id, formattted_actual_req_amt, formattted_paid_amt,formattted_balance, claim_details['comments'])
            else:
                print(f"Invalid email format: {employee_email}")


        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_claim', methods=['POST'])
def delete_claim():
    db = get_database()
    cursor = db.cursor()
    claim_id = request.form.get('claim_id')
    from_where = request.form.get('from_where')
    if claim_id:
        cursor = db.cursor()
        cursor.execute('DELETE FROM claims WHERE claim_id = ?', (claim_id,))
        db.execute('DELETE FROM claimed_items WHERE claim_no = ?', [claim_id])
        cursor.execute('DELETE FROM manual_entry WHERE cost_center_id = ?', (claim_id,))
        db.commit()
    if from_where == "admin":
        return redirect(url_for('admin_claims'))  # Redirect back to the page
    if from_where == 'profile':
        return redirect(url_for('prof_claim'))  # Redirect back to the page
    if from_where == 'accounts':
        return redirect(url_for('add_expense'))  # Redirect back to the page

def Claim_approval_Notification(employee_email, claim_by, claim_id, formattted_actual_req_amt, formattted_paid_amt,formattted_balance,Comments):

    # Establish connection with SMTP server
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    # Set subject
    subject = f"CES-Claim Approved - Claim ID: {claim_id}"

    # Create email body with approval details
    body = (
        f"Dear {claim_by},\n\n"
        f"We are pleased to inform you that your claim has been approved by the admin.\n\n"
        f"Here are the details of your claim:\n\n"
        f"Claim ID :  {claim_id}\n"
        f"Claimed Amount :  $ {formattted_actual_req_amt}\n"
        f"Paid Amount :  $ {formattted_paid_amt}\n"
        f"Balance :  $ {formattted_balance}\n\n"
        f"Comments : {Comments}\n\n"
        "If you have any questions or require further information, please feel free to contact us.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    # Construct the email
    message = MIMEMultipart()
    message['From'] = "cestimesheet67@gmail.com"
    message['To'] = employee_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    # Send the email
    s.sendmail("cestimesheet67@gmail.com", employee_email, message.as_string())

    # Quit the SMTP session
    s.quit()

@app.route('/fetch_claim_details_for_edit/<claim_id>')
def fetch_claim_details_for_edit(claim_id):
    db = get_database()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
    claim_details = cursor.fetchone()
    cursor.execute('SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC', (claim_id,))
    claim_items = cursor.fetchall()

    if claim_details:
        claim_details = dict(claim_details)
        
        # If 'approved_date' or 'approved_by' are None, fill with current date and user
        if claim_details.get('approved_date') is None:
            claim_details['approved_date'] = datetime.now().strftime('%Y-%m-%d')  # Current date in 'YYYY-MM-DD' format
        if claim_details.get('approved_by') is None:
            user = get_current_user()
            claim_details['approved_by'] = user['name']  # Assuming you have `current_user.name` for the logged-in user
    
    # Convert claim items to a list of dictionaries
    if claim_items:
        claim_items = [dict(row) for row in claim_items]
        for item in claim_items:
            # Round each value to two decimal places and then format to international numbering format
            item['amount'] = f"{round(item['amount'], 2):,.2f}"
            item['gst_value'] = f"{round(item['gst_value'], 2):,.2f}"
            item['gst'] = f"{round(item['gst'], 2):,.2f}"
            item['total'] = f"{round(item['total'], 2):,.2f}"

    
    # Return the updated claim details and claim items
    return jsonify({'claim_details': claim_details, 'claim_items': claim_items})

@app.route('/fetch_po_items/<po_no>')
def fetch_po_items(po_no):
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (po_no,))
    po_items = cursor.fetchall()
    
    # Assuming the po_items table has columns named as below; adjust if necessary
    po_items = [
        {
            'SN': index + 1,
            'ID': row['ID'],
            'Description': row['item'],
            'QTY': row['quantity'],
            'UOM': row['uom'],
            'Unit_Price': row['Unit_Price'],
            'Total_Price': row['total']
        } for index, row in enumerate(po_items)
    ]
    print(po_items)
    return jsonify({'po_items': po_items})

def send_claims_notification(receiver_email, claim_by, claim_id, status):
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    subject = "Claim Request Status Notification"
    body = (
        f"Dear {claim_by},\n\n"
        f"We are writing to inform you of the status of your claim request with ID {claim_id}. "
        f"After careful review, your claim has been {status}.\n\n"
        "Should you have any questions or require further assistance, please do not hesitate to reach out to us.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions")

    message = MIMEMultipart()
    message['From'] = "cestimesheet67@gmail.com"
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    
    s.sendmail("cestimesheet67@gmail.com", receiver_email, message.as_string())
    print('Leave notification email sent successfully.')
    s.quit()

def send_expenses_notification(receiver_email, claim_by, claim_id, status):
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    subject = "Expenses Request Status Notification"
    body = (
        f"Dear {claim_by},\n\n"
        f"We are writing to inform you of the status of your expenses request with ID {claim_id}. "
        f"After careful review, your expenses has been {status}.\n\n"
        "Should you have any questions or require further assistance, please do not hesitate to reach out to us.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions")

    message = MIMEMultipart()
    message['From'] = "cestimesheet67@gmail.com"
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    
    s.sendmail("cestimesheet67@gmail.com", receiver_email, message.as_string())
    print('Leave notification email sent successfully.')
    s.quit()

@app.route('/admin_delete_claim_item/<int:id>/<string:no>', methods=["GET", "POST"])
@login_required
def admin_delete_claim_item(id,no):
    user = get_current_user()
    if request.method == 'GET':
        # print("...........no",no)
        db = get_database()
        cursor = db.cursor()
        db.execute("DELETE FROM claimed_items WHERE id = ?", (id,))
        cursor.execute("SELECT SUM(total) FROM claimed_items WHERE claim_no = ?", (no,))
        total_sum = cursor.fetchone()[0]
        if total_sum is not None:
            total_sum = round(total_sum, 2)
        # print("...........total_sum",total_sum)

        cursor.execute("UPDATE claims SET claim_Total = ? WHERE claim_id = ?", (total_sum,no))
        cursor = db.execute("SELECT * FROM claims WHERE claim_id = ?", (no,))
        claim_details = cursor.fetchone()
        cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
        # Select rows with status "approved" for the last two months ordered by descending ID
        cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
        # Fetch the results
        open_claims = cursor_open.fetchall()
        approved_claims = cursor_approved.fetchall()
        # Combine the results
        claims = open_claims + approved_claims
        cursor = db.execute('SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC', (no,))
        claim_items = cursor.fetchall()
        db.commit()
        return render_template('admin_templates/admin/admin_claimedit.html', claim_no=no,claims=claims, claim_details=claim_details, user=user, claim_items=claim_items)

@app.route('/admin_delete_expenses_item/<int:id>/<string:no>', methods=["GET", "POST"])
@login_required
def admin_delete_expenses_item(id,no):
    user = get_current_user()
    if request.method == 'GET':
        # print("...........no",no)
        db = get_database()
        cursor = db.cursor()
        db.execute("DELETE FROM expences_items WHERE id = ?", (id,))
        cursor.execute("SELECT SUM(total) FROM expences_items WHERE claim_no = ?", (no,))
        total_sum = cursor.fetchone()[0]
        if total_sum is not None:
            total_sum = round(total_sum, 2)
        # print("...........total_sum",total_sum)

        cursor.execute("UPDATE Expenses SET claim_Total = ? WHERE claim_id = ?", (total_sum,no))
        cursor = db.execute("SELECT * FROM Expenses WHERE claim_id = ?", (no,))
        claim_details = cursor.fetchone()
        cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
        # Select rows with status "approved" for the last two months ordered by descending ID
        cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
        # Fetch the results
        open_claims = cursor_open.fetchall()
        approved_claims = cursor_approved.fetchall()
        # Combine the results
        claims = open_claims + approved_claims
        cursor = db.execute('SELECT * FROM expences_items WHERE claim_no = ? ORDER BY id DESC', (no,))
        claim_items = cursor.fetchall()
        db.commit()
        return render_template('admin_templates/admin/edit_expenses.html', claim_no=no,claims=claims, claim_details=claim_details, user=user, claim_items=claim_items)

@app.route('/deleteexpenses/<int:claimid>', methods=["GET", "POST"])
@login_required
def deleteexpenses(claimid):   
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        cursor = db.execute("SELECT claim_id FROM Expenses WHERE id = ?", (claimid,))
        claim_no = cursor.fetchone()[0]
        db.execute('DELETE FROM expences_items WHERE claim_no = ?', [claim_no])
        db.execute('DELETE FROM Expenses WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('admin_expenses'))
    return render_template('admin_expenses.html', user=user)

@app.route('/admin_expenses', methods=["POST", "GET"])
@login_required
def admin_expenses():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))
    visiblity = 'approve_claims'


    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_claim':
            id = request.form.get('claim_no')
            claim_id = request.form.get('claim_id')
            claim_Total = request.form.get('claim_Total')
            Reference_Code = request.form.get('Reference_Code')
            status = request.form.get('status')
            Approvedby = request.form.get('Approvedby')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            Edit_status = request.form.get('Edit_status')
            # Update the claims table
            db.execute('UPDATE Expenses SET claim_id = ?, claim_Total = ?, Reference_Code = ?,Edit_status = ?, status = ?, approved_by = ?, approved_date = ?, comments = ?, last_update = CURRENT_DATE WHERE claim_id = ?',
                       (claim_id, claim_Total, Reference_Code, Edit_status, status, Approvedby, Approved_date, Comments, id))
            db.commit()
            visiblity = 'approve_claims'
            flash(f'Claim with ID: {claim_id} updated successfully!', 'update_claim')

        if action == 'approve_claim':
            print('approve sairam')
            id = request.form.get('claim_no')
            claim_id = request.form.get('claim_id')
            claim_Total = request.form.get('claim_Total')
            Reference_Code = request.form.get('Reference_Code')
            status = 'Approved'
            Approvedby = request.form.get('Approvedby')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            cursor = db.execute('SELECT projectid, Sub_Category_code, claim_by,total FROM expences_items WHERE claim_no = ?', (claim_id,))
            temp_claim_items = cursor.fetchall()
            print(claim_id, claim_Total, Reference_Code, status, Approvedby, Approved_date, Comments, id)

            for row in temp_claim_items:
                project_id = row[0]  # Assuming project_id is stored in the first column of temp_claim_items
                code = row[1]  # Assuming project_type/code is stored in the second column of temp_claim_items
                claim_by = row[2]  # Assuming claim_by is stored in the third column of temp_claim_items
                total_cost = row[3]  # Assuming total cost is stored in the fourth column of temp_claim_items
                # Execute SQL query to check if the record already exists in manual_entry table
                if not code:
                    code = project_id
                cursor.execute("SELECT 1 FROM manual_entry WHERE department_code = ? AND project_id = ?", (code, project_id))
                existing_record = cursor.fetchone()

                if existing_record:
                    # Update the existing record
                    cursor.execute("UPDATE manual_entry SET added_cost = added_cost + ?, total = total + ? WHERE project_id = ? AND department_code = ?", (total_cost, total_cost, project_id, code))
                    print('updated',total_cost, total_cost, project_id, code)
                else:
                    # Insert a new record
                    cursor.execute("INSERT INTO manual_entry (project_id, department_code, cost, added_cost, total) VALUES (?, ?, ?, ?, ?)", (project_id, code, total_cost, total_cost, total_cost))
                    print('inserted',total_cost, total_cost, project_id, code)

            db.execute('UPDATE Expenses SET claim_id = ?, claim_Total = ?, Reference_Code = ?, status = ?, approved_by = ?, approved_date = ?, comments = ?, last_update = CURRENT_DATE WHERE claim_id = ?',
                       (claim_id, claim_Total, Reference_Code, status, Approvedby, Approved_date, Comments, id))
            db.commit()
            flash('Header updated successfully!', 'approve_claim')

            try:
                user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (claim_by,))
                mail_to_row = user_cur.fetchone()
                
                if mail_to_row:
                    mail_to = mail_to_row['name']
                else:
                    mail_to = 'sairam@gmail.com'
            except UnboundLocalError:
                mail_to = 'sairam@gmail.com'

            print(".......mail_to............", mail_to)

            # Sending the leave notification email
            send_expenses_notification(mail_to,claim_by, claim_id, status)

        if 'Delete' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            db = get_database()
            cursor = db.cursor()
            try:
                for claim_str in claimdata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM Expenses WHERE claim_id = ?', (claim_id,))
                    db.execute('DELETE FROM expences_items WHERE claim_no = ?', [claim_id])
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')


        return redirect(url_for('admin_expenses'))

    cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
    cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    claims = open_claims + approved_claims
    user_access = get_employee_access_control(user['name'])
    all_claims_cur = db.execute("SELECT * FROM Expenses ORDER BY id DESC;")
    all_claims = all_claims_cur.fetchall()
    return render_template('admin_templates/admin/admin_expenses.html',claims=claims, user = user,department_code=department_code,
                           visiblity=visiblity,user_access=user_access,all_claims=all_claims)

@app.route('/fetch_expenses_details/<string:claim_no>', methods=["GET"])
@login_required
def fetch_expenses_details(claim_no):
    db = get_database()
    cursor = db.execute('SELECT * FROM expences_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
    claim_items = cursor.fetchall()
    claim_items_dict = [dict(item) for item in claim_items]
    return jsonify({'claim_items': claim_items_dict})

from flask import jsonify
from datetime import datetime

@app.route('/get_material_receipt')
def get_material_receipt():
    po_number = request.args.get('po_number')
    db = get_database()

    # Step 1: Fetch Ordered Quantity for the given PO Number
    ordered_query = '''
        SELECT p.item, p.quantity AS ordered_qty
        FROM po_items p
        WHERE p.PO_number = ?
    '''
    cur = db.execute(ordered_query, (po_number,))
    ordered_rows = cur.fetchall()
    ordered_data = {row['item']: row['ordered_qty'] for row in ordered_rows}

    # Step 2: Fetch Material Receipt Data for the given PO Number
    receipt_query = '''
        SELECT 
            m.item_name,
            SUM(m.quantity) AS total_received_qty,
            m.uom,
            MAX(m.received_date) AS last_received_date,
            MAX(m.received_by) AS last_received_by
        FROM Material_Receipt m
        WHERE m.po_number = ?
        GROUP BY m.item_name
    '''
    cur = db.execute(receipt_query, (po_number,))
    receipt_rows = cur.fetchall()

    # Initialize a dictionary for material receipt data
    receipt_data = []
    receipt_items = {row['item_name']: row for row in receipt_rows}

    # For each ordered item, check if it has receipt data
    for item_name, ordered_qty in ordered_data.items():
        receipt_item = receipt_items.get(item_name)

        if receipt_item:
            received_qty = receipt_item['total_received_qty']
            balance_qty = ordered_qty - received_qty  # Calculate balance qty
            receipt_data.append({
                'item_name': item_name,
                'total_received_qty': received_qty,
                'ordered_qty': ordered_qty,
                'balance_qty': balance_qty,
                'uom': receipt_item['uom'] or '',  # If no UOM, leave it empty
                'last_received_date': receipt_item['last_received_date'] or '',  # If no date, leave it empty
                'last_received_by': receipt_item['last_received_by'] or ''  # If no user, leave it empty
            })
        else:
            # If no receipt found for this item, just show ordered quantity and no receipt data
            receipt_data.append({
                'item_name': item_name,
                'total_received_qty': 0,
                'ordered_qty': ordered_qty,
                'balance_qty': ordered_qty,  # If no receipt, balance qty is same as ordered
                'uom': '',  # No UOM
                'last_received_date': '',  # No date
                'last_received_by': ''  # No user
            })

    return jsonify(receipt_data)

@app.route('/fetch_cexpenses_details_for_edit/<claim_id>')
def fetch_cexpenses_details_for_edit(claim_id):
    db = get_database()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM Expenses WHERE claim_id = ?", (claim_id,))
    claim_details = cursor.fetchone()

    cursor.execute('SELECT * FROM expences_items WHERE claim_no = ? ORDER BY id DESC', (claim_id,))
    claim_items = cursor.fetchall()

    # Convert sqlite3.Row objects to dictionaries
    if claim_details:
        claim_details = dict(claim_details)
        # Check if 'claim_date' is None and set it to the current date if it is
        if claim_details.get('approved_date') is None:
            claim_details['approved_date'] = datetime.now().strftime('%Y-%m-%d')  # Set current date in YYYY-MM-DD format

    if claim_items:
        claim_items = [dict(row) for row in claim_items]

    return jsonify({'claim_details': claim_details, 'claim_items': claim_items})

@app.route('/pay_req', methods=["POST", "GET"])
@login_required
def pay_req():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))
    visibility = 'approve_claims'

    if request.method == 'POST':
        pay_req_id = request.form.get('pay_req_id')
        paid_id = request.form.get('paid')
        Canceled = request.form.get('Canceled')
        from datetime import datetime
        current_date = datetime.now().strftime('%Y-%m-%d')

        if Canceled:
            result = db.execute('''SELECT pay_number FROM payment_request WHERE id = ?''', (Canceled,))
            pay_number = result.fetchone()
            if pay_number:
                pay_number = pay_number[0]  # Extract pay_number from the result tuple
                db.execute('''DELETE FROM payment_req_items WHERE pay_number = ?''', (pay_number,))
                db.execute('''DELETE FROM payment_request WHERE pay_number = ?''', (pay_number,))
                db.commit()
            db.commit()

        elif pay_req_id:
            paid_amount = request.form.get('paid_amount')
            paid_date = request.form.get('paid_date')
            exchangerate = request.form.get('exchangerate')
            excurrency = request.form.get('excurrency')
            
            print("................excurrency............", excurrency)
            print("................exchangerate............", exchangerate)

            paid_amount_actual = float(paid_amount) if paid_amount and paid_amount != 'None' else 0.0
            exchangerate = float(exchangerate) if exchangerate and exchangerate != 'None' else 1.0
            excurrency = excurrency or 'SGD'

    

            # Get pay_number and po_number
            cursor.execute("SELECT pay_number, po_number FROM payment_request WHERE id = ?", (pay_req_id,))
            result = cursor.fetchone()
            pay_number = result['pay_number']
            po_number = result['po_number']

            # Insert foreign currency amount into payment history
            db.execute('''
                INSERT INTO payment_request_history (pay_number, pay_date, po_number, paid_by, amount)
                VALUES (?, ?, ?, ?, ?)
            ''', (pay_number, paid_date, po_number, user['name'], paid_amount_actual))
            db.commit()

            # Get actual request amount in SGD
            cursor.execute("SELECT overall_total_amount FROM payment_request WHERE id = ?", (pay_req_id,))
            result = cursor.fetchone()
            actual_request_amount_sgd = float(result[0]) if result and result[0] is not None else 0.0

            # Calculate total past paid in SGD (convert each entry if needed separately in future)
            cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM payment_request_history WHERE pay_number = ?", (pay_number,))
            past_paid_amount = cursor.fetchone()[0]

            row_balance = actual_request_amount_sgd - past_paid_amount

            print("................actual_request_amount (SGD)............", actual_request_amount_sgd)
            print("................past_paid_amount (foreign)............", past_paid_amount)
            print("................row_balance............", row_balance)

            if past_paid_amount >= actual_request_amount_sgd:
                pay_status = "Paid"
            elif past_paid_amount > 0:
                pay_status = "Partial"
            else:
                pay_status = "Pending"

            db.execute(''' UPDATE payment_request SET status = ?, paid_by = ?, paid_date = ?, balence = ? WHERE id = ?  ''', 
                       (pay_status, user['name'], paid_date, row_balance, pay_req_id))

        

            if po_number:
                total_query = "SELECT COALESCE(SUM(overall_total_amount), 0) FROM payment_request WHERE pay_number = ?"
                total_amount = db.execute(total_query, (pay_number,)).fetchone()[0]
                po_items_query = "SELECT COALESCE(SUM(total), 0), COALESCE(MAX(GST), 0) FROM po_items WHERE PO_number = ?"
                po_items_total, gst_percentage = db.execute(po_items_query, (po_number,)).fetchone()
                gst_value = (po_items_total * gst_percentage / 100) if gst_percentage > 2 else 0
                po_actual = po_items_total + gst_value
                history_query = "SELECT COALESCE(SUM(amount), 0) FROM payment_request_history WHERE po_number = ?"
                past_paid_amount = db.execute(history_query, (po_number,)).fetchone()[0]  # Get the total previous payments
                balance = round(po_actual -  past_paid_amount, 2)


                if balance == 0:
                    payment_status = 'Closed'
                    query = "SELECT do_staus FROM created_po WHERE PO_no = ?"
                    result = db.execute(query, (po_number,)).fetchone()
                    if result is None:
                        do_status = None
                    else:
                        do_status = result[0]  # Extract value safely

                    if do_status == 'Closed':
                        update_query = "UPDATE created_po SET status = ? WHERE PO_no = ?"
                        db.execute(update_query, ('Closed', po_number))
                        
   
                elif balance > 0:
                    payment_status = 'Partial'
                else:
                    payment_status = 'Open'  # Handles cases where no payment has been made
                update_query = "UPDATE created_po SET payment_status = ? WHERE PO_no = ?"
                db.execute(update_query, (payment_status, po_number))
                
            db.commit()

            mail_to_list = []
            user_cur = db.execute('SELECT pay_number, invoice_no, proj_no, po_number, approved_by, overall_total_amount, created_by, paid_by FROM payment_request WHERE id = ?', (pay_req_id,))
            request_details = user_cur.fetchone()  # Fetch only one row

            team_cur = db.execute('SELECT name FROM admin_user WHERE username = ?',(request_details[6],))
            mail_to_list = [row[0] for row in team_cur.fetchall()]
            roles_cur = db.execute('''SELECT employee FROM roles WHERE primary_role_code = 18 OR sencondary_role_code = 18''')
            employees_with_role_11 = [row[0] for row in roles_cur.fetchall()]
            if employees_with_role_11:
                placeholders = ', '.join(['?'] * len(employees_with_role_11))
                query = f'SELECT name FROM admin_user WHERE username IN ({placeholders})'
                names_cur = db.execute(query, employees_with_role_11)
                mail_to_list.extend([row[0] for row in names_cur.fetchall()])
            mail_to_list = list(set(mail_to_list))
            import re
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            valid_emails = []
            for email in mail_to_list:
                if re.match(email_regex, email):
                    valid_emails.append(email)  # Add to valid email list

            # Payment_Request_paid_Notification(valid_emails, request_details)
            try:
                # Payment_Request_paid_Notification(valid_emails, request_details)
                print("Email sent...........:")

            except Exception as e:
                print("Email sending failed but continuing:", e)

            return redirect(url_for('pay_req'))

       
        return redirect(url_for('pay_req'))

    cursor = db.execute('SELECT * FROM payment_request   ORDER BY id DESC')
    payment_request = cursor.fetchall()
    rows = []

    for pay in payment_request:
        id = pay[0]            # The ID column is at index 0
        pay_number = pay[1]
        invoice_no = pay[2]
        pay_date = pay[3]
        proj_no = pay[4]
        po_number = pay[5]
        status = pay[6]
        created_by = pay[7]
        approved_by = pay[8]
        paid_by = pay[9]
        amount = pay[10]
        invoice_file_name = pay[11]
        paid_date = pay[12]
        approved_date = pay[13]
        overall_total_amount = pay[14]
        Invoice_date = pay[15]
        gst_stat = pay[16]
        gst_value = pay[17]
        supplier_name = pay[18]
        project_name = pay[19]
        Terms = pay[20]
        time_period = pay[21]
        balence = pay[22] if pay[22] is not None else 0.0

        po_cursor = db.execute("SELECT do_staus FROM created_po WHERE PO_no = ?", (po_number,))
        po_result = po_cursor.fetchone()
        do_status = po_result[0] if po_result else None


        from datetime import datetime, timedelta

        if Invoice_date:
            try:
                invoice_date = datetime.strptime(Invoice_date, "%Y-%m-%d")
                today = datetime.today().date()  # Get current date without time

                if time_period in ['Days', 'Advance']:
                    try:
                        terms_int = int(Terms)  # Ensure Terms is an integer
                        due_date = invoice_date + timedelta(days=terms_int)  # Calculate due date
                        due_days = (due_date.date() - today).days  # Days remaining from today
                    except ValueError:
                        due_date = None
                        due_days = None
                        print("Invalid value for 'Terms', expected an integer.")

                elif time_period == 'COD':  # Payment is due immediately
                    due_date = invoice_date
                    due_days = None  # Due today

                else:
                    due_date = None
                    due_days = None

                due_date_str = due_date.strftime("%m/%d/%y") if due_date else '0/0/0'

            except ValueError:
                print("Invalid Invoice_date format, expected YYYY-MM-DD.")
                due_date = None
                due_days = None
                due_date_str = '0/0/0'
        
        else:
            due_date = None
            due_days = None
            due_date_str = '0/0/0'

        rows.append({ 'id': id,'pay_number': pay_number, 'invoice_no': invoice_no,  'pay_date': pay_date, 
                     'proj_no': proj_no,'po_number': po_number, 'status': status, 'created_by': created_by, 'amount' : amount,
                    'approved_by': approved_by, 'paid_by': paid_by, 'invoice_file_name' : invoice_file_name,
                    'paid_date' : paid_date, 'approved_date' : approved_date, 'overall_total_amount' :overall_total_amount,
                     'Invoice_date' : Invoice_date,  'gst_stat': gst_stat, 'gst_value' : gst_value, 'supplier_name':supplier_name,
                       'project_name':project_name,'Terms': Terms,'time_period':time_period ,'due_date':due_date_str,
                        'due_days': due_days,'balence': balence,'do_status': do_status  })

    grouped_df = pd.DataFrame(rows)

    if 'status' in grouped_df.columns:
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3})
        grouped_df = grouped_df.sort_values('status_order')
    
    else:
        # print("The 'status' column is missing from rows.")
        grouped_df['status'] = 'Unknown'  # Add a default status or handle differently
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3}).fillna(0)
        grouped_df = grouped_df.sort_values('status_order')

    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/admin/pay_req.html',user_access=user_access,grouped_df=grouped_df,
                           visibility=visibility, user = user,department_code=department_code)

import os
from flask import send_from_directory

UPLOAD_FOLDER = os.path.abspath(r'docment_data\payment_request_invoices')  # Set your attachment folder

@app.route('/get_payment_details')
def get_payment_details():
    id = request.args.get('pay_number')
    db = get_database()
    cursor = db.cursor()

    # Get the payment_request row
    payment = cursor.execute("SELECT * FROM payment_request WHERE id = ?", (id,)).fetchone()
    if not payment:
        return jsonify({'success': False, 'message': 'Payment request not found'})

    payment_dict = dict(payment)
    pay_number = payment_dict['pay_number']
    po_number = payment_dict['po_number']

    # Get associated items and history
    items = cursor.execute("SELECT * FROM payment_req_items WHERE pay_number = ?", (pay_number,)).fetchall()
    history_items = cursor.execute("SELECT * FROM payment_request_history WHERE po_number = ?", (po_number,)).fetchall()


    created_po = cursor.execute("SELECT * FROM created_po WHERE PO_no = ?", (po_number,)).fetchone()
    print("..created_po['Discount']...........",created_po['Discount'])

    po_items = cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (po_number,)).fetchall()
    po_total = 0.0

    for item in po_items:
        try:
            item_total = float(item['total']) if item['total'] else 0.0
        except (ValueError, TypeError):
            item_total = 0.0

        try:
            gst_percent = float(item['GST']) if item['GST'] else 0.0
        except (ValueError, TypeError):
            gst_percent = 0.0

        gst_value = item_total * (gst_percent / 100)
        po_total += item_total + gst_value

    # Apply Discount from created_po
    try:
        discount_percent = float(created_po['Discount']) if created_po['Discount'] else 0.0
    except (ValueError, TypeError):
        discount_percent = 0.0

    discount_amount = (po_total * discount_percent) / 100
    po_total_after_discount = po_total - discount_amount


    return jsonify({
        'success': True,
        'payment': payment_dict,
        'items': [dict(item) for item in items],
        'history_items': [dict(history_item) for history_item in history_items],
        'po_items': [dict(po_item) for po_item in po_items],
        'created_po': dict(created_po) if created_po else None,
        'po_total': round(po_total_after_discount, 2),
    })


# Route to serve the file for download/view
@app.route('/download_attachment/<filename>')
def download_attachment(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def Payment_Request_paid_Notification(valid_emails, request_details):
    sender_email = "cestimesheet67@gmail.com"
    sender_password = "rmlomkpnujzzvlsy"  # Consider using environment variables

    subject = f"{request_details[0]}"
    body = (
        f"Dear Sir/Madam,\n\n"
        f"This is to inform you that your payment request has been paid by {request_details[7]}.\n\n"
        f"Request Details:\n"
        f"Payment Request ID : {request_details[0]}\n"
        f"Amount : $ {request_details[5]:,.2f}\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    server = None  # Always initialize for safe cleanup
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)

        for recipient in valid_emails:
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = recipient
            message["Subject"] = subject
            message.attach(MIMEText(body, "plain"))

            server.sendmail(sender_email, recipient, message.as_string())
            print(f"Payment notification sent successfully to: {recipient}")

    except Exception as e:
        print(f"Error sending payment notification email: {e}")  # Do not raise error

    finally:
        if server:
            server.quit()

@app.route('/proj_budget', methods=["POST", "GET"])
@login_required
def proj_budget():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])

    if department_code != 1000:
        return redirect(url_for('login'))

    user_access = get_employee_access_control(user['name'])

    cursor.execute("""
        SELECT id, project_name, client, po_value, end_time 
        FROM projects 
        WHERE status != 'Closed' 
        ORDER BY id DESC
    """)
    projects = cursor.fetchall()

    project_data = []

    for project in projects:
        project_id, project_name, client, po_value, end_time = project

        # --- Budget: sum of total * hourly_rate ---
        cursor.execute("""
            SELECT p.department_code, 
                   COALESCE(SUM(p.total), 0), 
                   COALESCE(c.hourly_rate, 1)
            FROM pmtable p
            LEFT JOIN cost_center c ON p.department_code = c.code
            WHERE p.project_id = ?
            GROUP BY p.department_code
        """, (project_id,))
        budget_rows = cursor.fetchall()
        # final_budget_sum = sum(round(total * hourly_rate, 2) for _, total, hourly_rate in budget_rows)
        final_budget_sum = round(sum(total * hourly_rate for _, total, hourly_rate in budget_rows), 2)


        # --- Actuals from manual_entry ---
        cursor.execute("""
            SELECT COALESCE(SUM(
                CASE 
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                    ELSE ((cost / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ), 0)
            FROM manual_entry
            WHERE project_id = ?
        """, (project_id,))
        actuals_manual = cursor.fetchone()[0]

        # --- Actuals from working hours ---
        working_hr = actual_cost_for_working_hr(project_id)
        total_actuals = working_hr + actuals_manual

        # --- Invoicing ---
        cursor.execute("SELECT SUM(amount) FROM created_invoice WHERE prj_id = ?", (project_id,))
        Inv_total = cursor.fetchone()[0] or 0

        cursor.execute("SELECT SUM(amount) FROM created_invoice WHERE prj_id = ? AND status = 'Paid'", (project_id,))
        Inv_received = cursor.fetchone()[0] or 0

        cursor.execute("SELECT SUM(amount) FROM created_invoice WHERE prj_id = ? AND status != 'Paid'", (project_id,))
        Inv_balance = cursor.fetchone()[0] or 0

        # --- Final Append ---
        project_data.append({
            'id': project_id,
            'project_name': project_name,
            'client': client,
            'po_value': po_value,
            'end_time': end_time,
            'budget': round(final_budget_sum, 2),
            'actuals': round(total_actuals, 2),
            'Inv_total': round(Inv_total, 2),
            'Inv_received': round(Inv_received, 2),
            'Inv_balance': round(Inv_balance, 2)
        })

    # Overhead Budget Data
    cursor.execute("SELECT * FROM overhead_budget")
    oh_budget = cursor.fetchall()

    return render_template(
        'admin_templates/admin/proj_budget.html',
        user_access=user_access,
        user=user,
        department_code=department_code,
        project_list=project_data,
        oh_budget=oh_budget
    )

def actual_cost_for_working_hr(project_id):
    db = get_database()
    cursor = db.cursor()

    cursor.execute("""
        SELECT w.total_cost, COALESCE(a.rate_per_hour, 1)
        FROM workingHours w
        LEFT JOIN admin_user a ON w.employeeID = a.username
        WHERE w.projectID = ?
    """, (project_id,))

    final_actual_cost = sum((total_cost if total_cost is not None else 0) * 
                             (rate_per_hour if rate_per_hour is not None else 1)
                             for total_cost, rate_per_hour in cursor.fetchall())

    

    return(final_actual_cost)  

@app.route('/proj_status', methods=["POST", "GET"])
@login_required
def proj_status():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code1 = get_department_code_by_username(user['name'])
    if department_code1 != 1000:
        return redirect(url_for('login'))

    from datetime import datetime
    cursor.execute("SELECT code, expenses_name FROM cost_center ORDER BY CAST(code AS INTEGER) ASC")
    data = {str(row[0]): {'role': row[1]} for row in cursor.fetchall()}
    cursor.execute(""" SELECT department_code, COUNT(*)  FROM admin_user  GROUP BY department_code """)
    user_counts = cursor.fetchall()

    for department_code, user_count in user_counts:
        str_code = str(department_code)
        if str_code in data:
            data[str_code]['qty'] = user_count

    cursor.execute("""SELECT code, available_hrs, annual_hrs, medical_hrs FROM department_hrs_alloc""")
    hrs_data = { str(row[0]): { 'available_hrs': row[1] if row[1] is not None else 0, 'annual_hrs': row[2] if row[2] is not None else 0, 'medical_hrs': row[3] if row[3] is not None else 0 }
        for row in cursor.fetchall() }

    # print("..2...data...........",data)

    for code in data:
        if code in hrs_data:
            data[code].update(hrs_data[code])
        else:
            data[code].update({ 'available_hrs': 0, 'annual_hrs': 0, 'medical_hrs': 0})

    # print("...4..data...........",data)


    for code in data:
        available_hrs = data[code].get('available_hrs', 0)
        data[code]['available_hrs'] = available_hrs  

    # print("..3...data...........",data)

    current_year = datetime.now().year
    cursor.execute(""" SELECT COUNT(*) FROM public_holidays WHERE date LIKE ? """, (f'{current_year}%',))
    holiday_count = cursor.fetchone()[0]
    total_holiday_hours = holiday_count * 8
    for code in data:
        data[code]['holiday_hrs'] = total_holiday_hours

    cursor.execute("SELECT date FROM public_holidays")
    holiday_dates = set(row[0] for row in cursor.fetchall())

    today = datetime.today().date()
    end_date = datetime(today.year, 12, 31).date()  

    working_days = 0
    current_day = today
    while current_day <= end_date:
        if (current_day.weekday() < 5 and  # 0-4 = Mon-Fri
            str(current_day) not in holiday_dates):
            working_days += 1
        current_day += timedelta(days=1)

    remaining_hours_total = working_days * 10
    cursor.execute(""" SELECT department_code, SUM(total) FROM pmtable WHERE CAST(department_code AS INTEGER) < 1999 GROUP BY department_code""")
    allocated = dict(cursor.fetchall())  
    cursor.execute(""" SELECT departmentID, SUM(hoursWorked) FROM workingHours GROUP BY departmentID """)
    worked = dict(cursor.fetchall())  
    balance_hours = {}

    for dept in allocated:
        worked_hours = worked.get(dept, 0)
        balance_hours[dept] = allocated[dept] - worked_hours
    
    # print(".....balance_hours...........",balance_hours)


    for code in data:
        available_hrs = data[code].get('available_hrs', 0)
        annual_hrs = data[code].get('annual_hrs', 0)
        medical_hrs = data[code].get('medical_hrs', 0)
        holiday_hrs = data[code].get('holiday_hrs', 0)

        actual_hrs = available_hrs - (annual_hrs + medical_hrs + holiday_hrs)
        data[code]['actual_hrs'] = actual_hrs
        data[code]['remaining_hours'] = remaining_hours_total  # or use a different variable name if needed

        qty = data[code].get('qty', 0)
        total_hrs = remaining_hours_total * qty
        data[code]['total_hrs'] = total_hrs

        dept = str(code)  # ensure it's a string
        balance = balance_hours.get(dept, 0)
        data[code]['balance_hrs'] = balance

        diff = balance - total_hrs 
        data[code]['Difference'] = diff

        if remaining_hours_total != 0:
            resultvalue = diff / remaining_hours_total
        else:
            resultvalue = 0

        data[code]['result'] = round(resultvalue, 2)


 


    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/admin/proj_status.html',
                         user_access=user_access, user=user, department_code=department_code1,data=data)

import datetime
def suggest_hiring(department_data, total_hours_per_employee, future_growth_factor=1.2):
    from datetime import datetime

    hiring_suggestions = []

    # Calculate total predicted remaining hours across all departments
    total_predicted_remaining_hours = 0
    import datetime
    # Get the current day of the year
    current_date = datetime.datetime.now()
    start_of_year = datetime.datetime(current_date.year, 1, 1)
    remaining_days_in_year = (datetime.datetime(current_date.year + 1, 1, 1) - current_date).days

    # Count remaining weekends (Saturdays and Sundays)
    remaining_weekends = 0
    for i in range(remaining_days_in_year):
        current_day = current_date + datetime.timedelta(days=i)
        if current_day.weekday() == 5 or current_day.weekday() == 6:  # 5 is Saturday, 6 is Sunday
            remaining_weekends += 1

    # Assuming 8 hours per workday
    work_hours_per_day = 8
    work_hours_per_weekend = 16  # 8 hours for Saturday + 8 hours for Sunday

    for dept_code, data in department_data.items():
        remaining = data['remaining_hours']
        available_hours = data['Available_hours']

        # Current hiring suggestion based on remaining hours
        if remaining < 0:
            employees_needed = abs(remaining) // total_hours_per_employee + 1
            suggestion = f"Department {data['Description']} (Code: {dept_code}) is over budget by {abs(remaining)} hours. Hire {employees_needed} more employee(s)."
            hiring_suggestions.append(suggestion)

        elif remaining < total_hours_per_employee * 0.2:
            suggestion = f"Department {data['Description']} (Code: {dept_code}) has {remaining} hours left. Hire at least 1 more employee."
            hiring_suggestions.append(suggestion)

        # Future hiring prediction based on available hours
        predicted_available_hours = available_hours + (remaining_days_in_year - remaining_weekends) * work_hours_per_day * future_growth_factor
        predicted_remaining_hours = predicted_available_hours - data['actual_hours']

        # Predict future hiring needs if the department will continue working at current pace
        if predicted_remaining_hours < 0:
            future_employees_needed = abs(predicted_remaining_hours) // total_hours_per_employee + 1
            future_suggestion = f"Future Prediction: Department {data['Description']} (Code: {dept_code}) will overrun available hours by {abs(predicted_remaining_hours)} hours. Hire {future_employees_needed} more employee(s)."
            hiring_suggestions.append(future_suggestion)
        elif predicted_remaining_hours < total_hours_per_employee * 0.2:
            future_suggestion = f"Future Prediction: Department {data['Description']} (Code: {dept_code}) will have {predicted_remaining_hours} hours left. Hire at least 1 more employee."
            hiring_suggestions.append(future_suggestion)

        # Add total predicted remaining hours for the overall suggestion
        total_predicted_remaining_hours += predicted_remaining_hours

        # Add individual department suggestion based on predicted remaining hours
        if predicted_remaining_hours < total_hours_per_employee * 0.2:
            department_suggestion = f"Department {data['Description']} (Code: {dept_code}) will have {predicted_remaining_hours} hours left. Hire at least 1 more employee."
            hiring_suggestions.append(department_suggestion)

    # Add overall hiring suggestion based on total predicted remaining hours
    if total_predicted_remaining_hours < total_hours_per_employee * 0.2 * len(department_data):
        overall_suggestion = f"Overall prediction: The total predicted remaining hours across all departments is {total_predicted_remaining_hours}. Hire additional employees to cover at least {len(department_data)} departments."
        hiring_suggestions.append(overall_suggestion)

    return hiring_suggestions

@app.route('/ac_add', methods=["POST", "GET"])
@login_required
def ac_add():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username(user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))

    cursor.execute("SELECT id, code, expenses_name, budget, added, total FROM overhead_budget")
    overhead_data = cursor.fetchall()
    overhead_list = [{ "id": row[0], "code": row[1], "expenses_name": row[2], "budget": row[3], "added": row[4], "total": row[5]} for row in overhead_data]
    user_access = get_employee_access_control(user['name'])

    return render_template('admin_templates/admin/ac_add.html',user_access=user_access,user=user,department_code=department_code,overhead_list=overhead_list )

@app.route('/submit-overhead-budget', methods=['POST'])
def submit_overhead_budget():
    data = request.json.get('rows', [])
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        db = get_database()
        cursor = db.cursor()
        cursor.execute("DELETE FROM overhead_budget")

        for row in data:
            total = row['budget'] + row['added']
            cursor.execute(""" INSERT INTO overhead_budget (code, expenses_name, budget, added, total) VALUES (?, ?, ?, ?, ?)
            """, (row['code'], row['expenses_name'], row['budget'], row['added'], total))

        db.commit()
        return jsonify({"message": "Data submitted and inserted successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete-overhead-row/<int:row_id>', methods=['DELETE'])
def delete_overhead_row(row_id):
    try:
        db = get_database()
        cursor = db.cursor()
        cursor.execute("DELETE FROM overhead_budget WHERE id = ?", (row_id,))
        db.commit()
        return jsonify({"message": "Row deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/po_status', methods=["POST", "GET"])
@login_required
def po_status():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    if department_code != 1000:
        return redirect(url_for('login'))
    user_access = get_employee_access_control(user['name'])

    po_query = """
        SELECT
            p.id AS prj_id,
            po.PO_no,
            po.Supplier_Name, 
            SUM(CAST(pi.total AS FLOAT)) AS Item_Value,
            SUM((pi.GST / 100.0) * (pi.Unit_Price * pi.quantity)) AS GST_Value,
            SUM(CAST(pi.total AS FLOAT)) + SUM((pi.GST / 100.0) * (pi.Unit_Price * pi.quantity)) AS total_po_value,
            po.do_staus
        FROM projects p
        JOIN created_po po ON p.id = po.project_id
        JOIN po_items pi ON po.PO_no = pi.PO_number
        WHERE p.status != 'Closed'
        AND p.id != 1
        AND po.status != 'Closed'
        GROUP BY p.id, po.PO_no, po.Supplier_Name
        ORDER BY p.id DESC;
    """
    cursor.execute(po_query)
    po_results = cursor.fetchall()

    po_list = []
    for po_row in po_results:
        current_po_number = po_row[1] 
        payment_query = """ SELECT SUM(overall_total_amount) AS total_requested_amount, SUM(balence) AS total_paid_amount FROM payment_request WHERE po_number = ?;"""
        cursor.execute(payment_query, (current_po_number,))
        payment_data = cursor.fetchone()
        requested_amount_for_po = round(payment_data[0] if payment_data[0] is not None else 0.0, 2)
        paid_amount_for_po = round(payment_data[1] if payment_data[1] is not None else 0.0, 2)
        paid_amount = requested_amount_for_po - paid_amount_for_po

        if paid_amount == 0:
            paid_amount = requested_amount_for_po

    
        po_list.append(
            {
                "prj_id": po_row[0],
                "PO_NO": po_row[1],
                "Supplier_Name": po_row[2],
                "Item_Value": round(po_row[3], 2),
                "GST_Value": round(po_row[4], 2),
                "total_po_value": round(po_row[5], 2),
                "do_staus": po_row[6],
                "paid_amount": paid_amount         
            }
        )

    print("......po_list...........\n", po_list)

    # Print data for the first 5 PO's
    print("\n----- First 5 POs with Payment Details -----")
    for i, po in enumerate(po_list[:5]):
        print(f"PO {i+1}:")
        for key, value in po.items():
            print(f"  {key}: {value}")
        print("-" * 30)

    return render_template('admin_templates/admin/po_status.html', user_access=user_access, user=user, department_code=department_code, po_list=po_list)


@app.route('/create_prj', defaults={'project_id': None}, methods=["POST", "GET"])
@app.route('/create_prj/<int:project_id>', methods=["POST", "GET"])
@login_required
def create_prj(project_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    db = get_database()  
    cursor = db.cursor()
    cursor.execute(""" SELECT id, project_name, po_value, budget, requested_by, approved_status FROM projects_request """)
    project_requests = cursor.fetchall()
    # Print the fetched data
    show = 'new_prj_req'
    project_details =None
    resources =  None
    stage = None

    if project_id:
        project_details = db.execute("SELECT * FROM projects_request WHERE id = ?", (project_id,)).fetchone()
        resource_details = db.execute("SELECT * FROM request_pmtable WHERE project_id = ?", (project_id,)).fetchall()
        resources = {resource['department_code']: resource['hours'] for resource in resource_details}
        stage = 'edit'

    if request.method == 'POST':

        action = request.form.get('action')  # Get the action from the clicked button
        # print("Action:", action)

        project_id = request.form.get('project_id', type=int)
        # print("............project_id............",project_id)

        # Collect form data
        projectId = request.form['projectid']
        client = request.form['client']
        projectName = request.form['projectname']
        startTime = request.form['start_time']
        endTime = request.form['end_time']
        status = request.form['status']
        po_number = request.form['po_number']
        po_value = request.form['po_value']
        # print("..........po_value.................",po_value)
        pm = request.form['projectmanager']
        budget = request.form['budget']
        billing_address =request.form['billing_address1']
        billing_address2 =request.form['billing_address2']
        billing_address3 =request.form['billing_address3']
        delivery_address = request.form['delivery_address1']
        delivery_address2 = request.form['delivery_address2']
        delivery_address3 = request.form['delivery_address3']
        type = request.form['type']
        selected_members = request.form.get('selected_members', '')
        # print("......selected_members........\n",selected_members)
        from datetime import datetime
        current_date = datetime.now().strftime('%Y-%m-%d')  # Format: YYYY-MM-DD



        if action == "create_project":

            # print("Creating new project")
            resources12 = {}
            for key in request.form:
                if key.isdigit():  # Match numeric keys like '1000', '1001', etc.
                    value = request.form.get(key)
                    resources12[key] = float(value) if value else 0.0  # Convert to float and set 0.0 if empty
            # Insert or update into request_pmtable
            for department_code, hours in resources12.items():
                # Check if a record already exists
                existing_record = db.execute(""" SELECT COUNT(*) FROM request_pmtable WHERE project_id = ? AND department_code = ? """, (projectId, department_code)).fetchone()[0]
                if existing_record:
                    # Update the existing record
                    db.execute(""" UPDATE request_pmtable SET hours = ?, total = ? WHERE project_id = ? AND department_code = ?""", (hours, hours, projectId, department_code))
                else:
                    # Insert a new record
                    db.execute(""" INSERT INTO request_pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?) """, (projectId, department_code, hours, 0.0, hours))
                
                db.execute("INSERT INTO pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?)", (projectId, department_code, hours, 0.0, hours))
                import datetime
                current_date = datetime.date.today()  # Get current date
                    # Insert data into alloc_hrs_pmtable
                if hours > 0:
                    db.execute(""" INSERT INTO alloc_hrs_pmtable (project_id, username, department_code, total, date_added) VALUES (?, ?, ?, ?, ?)
                    """, (projectId, user['name'], department_code, hours, current_date))
                    db.commit()
                db.commit()

            cre_cal_budget = calculate_budget(resources12)
            # print(f'..............cre_cal_budget...........: {cre_cal_budget}')

            db.execute("UPDATE projects_request SET approved_status = ?, created_by = ?, created_date = ?  WHERE id = ?", ('Created',user['name'],current_date, projectId))
            db.commit()
            db.execute(""" UPDATE projects_request SET  client = ?, project_name = ?, start_time = ?, end_time = ?, status = ?, po_number = ?, po_value = ?, pm = ?, 
               delivery_address = ?, billing_address = ?, budget = ?, type = ?, project_members = ?, approved_status = ?,
                       billing_address2 = ?,billing_address3 = ?,delivery_address2 = ?,delivery_address3 = ? WHERE id = ? """, 
               (client, projectName, startTime, endTime, status, po_number, po_value, pm,  delivery_address, billing_address, cre_cal_budget, type, selected_members,
                 'Created', billing_address2,billing_address3,delivery_address2,delivery_address3, projectId))
            db.execute('''INSERT INTO projects (id, client, project_name, start_time, end_time, pm_status, pe_status, status, po_number, pm, po_value, budget, billing_address, 
                         delivery_address,type, project_members,billing_address2,billing_address3,delivery_address2,delivery_address3) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        [projectId, client, projectName, startTime, endTime, 1, 1, status, po_number, pm, po_value, cre_cal_budget, billing_address, delivery_address, type, 
                         selected_members,billing_address2,billing_address3,delivery_address2,delivery_address3])
            db.commit()


            # Step 1: Fetch project_members and pm from the projects table
            query = "SELECT project_members, pm FROM projects WHERE id = ?;"
            cursor.execute(query, (projectId,))
            result = cursor.fetchone()

            if result:
                project_members, pm = result

                # Create a set for project members (assuming project_members are comma-separated)
                members_set = set(project_members.split(',')) if project_members else set()

                # Add the PM to the set
                if pm:
                    members_set.add(pm)

                # Clean up and strip any extra spaces
                members_set = {member.strip() for member in members_set}

                # Debug: Print the combined set
                # print("Combined Set of Members:", members_set)

                # Step 2: Fetch emails for the selected usernames and additional department codes
                query = """ SELECT au.name FROM admin_user au WHERE au.username IN ({}) OR au.department_code IN (1000, 10, 20) """.format(','.join(['?'] * len(members_set)))
                # Execute the query with members_set as parameters
                cursor.execute(query, list(members_set))
                email_ids = [row[0] for row in cursor.fetchall()]  # Extract the emails from the query result

                # Debug: Print the email IDs
                # print("Email IDs:", email_ids)
                import re
                # Validate and filter email addresses
                email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                valid_emails = [email for email in email_ids if re.match(email_regex, email)]

                if valid_emails:
                    print("Valid Emails:", valid_emails)
                    # Send email notifications
                    # Project_created_by_admin_Notification(valid_emails, pm, members_set, projectId)
            else:
                print(f"No project found with ID {projectId}.")

            show = 'new_prj_req'
            flash('Project Is Created successfully..', 'prj_req')
            return redirect(url_for('create_prj'))


    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    teamlist1 = [row[0] for row in cursor.fetchall()]
    teamlist = sorted(teamlist1, key=lambda x: x.lower())
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= 10 AND department_code <= 1017')
    pmlist1 = [row[0] for row in cursor.fetchall()]
    pmlist = sorted(pmlist1, key=lambda x: x.lower())
    cursor.execute('''SELECT EnquiryNumber FROM enquiries WHERE status = 'Won' AND EnquiryNumber NOT IN (SELECT id FROM projects_request) 
                   AND EnquiryNumber NOT IN (SELECT id FROM projects) ORDER BY EnquiryNumber DESC ''')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    user_access = get_employee_access_control(user['name'])
    query = """ SELECT COALESCE(COUNT(*), 0) FROM projects_request WHERE approved_status != 'Created' AND approved_status IS NOT NULL;"""
    # Execute the query and fetch the result
    cursor.execute(query)
    pending_req = cursor.fetchone()[0]  # Get the first element from the result tuple

    # Print the result (this is optional)
    # print(f"The count of approved_status not equal to 'Created' is: {pending_req}")
    return render_template('admin_templates/admin/create_prj.html',user_access=user_access,department_code=department_code,user=user,usernames=usernames,show=show,
                          stage=stage,project_ids=project_ids, pmlist=pmlist,teamlist=teamlist,project_requests=project_requests,project=project_details, resources=resources,
                          pending_req=pending_req, csrf_token=request.form.get('csrf_token'))

@app.route("/save_depart_hours", methods=["POST"])
def save_depart_hours():
    data = request.get_json()
    print('......data...............', data)

    code = data.get("code")
    available_hrs = data.get("available_hrs")
    annual_hrs = data.get("annual_hrs")
    medical_hrs = data.get("medical_hrs", 0.0)
    role = data.get("role")
    budget_hrs = data.get("budget_hrs")  # This may or may not be provided

    try:
        db = get_database()
        cursor = db.cursor()

        # Check if the code exists
        cursor.execute("SELECT * FROM department_hrs_alloc WHERE code = ?", (code,))
        existing_row = cursor.fetchone()

        if existing_row:
            # Update existing row, considering budget_hrs conditionally
            if budget_hrs is not None:
                cursor.execute("""
                    UPDATE department_hrs_alloc 
                    SET available_hrs = ?, annual_hrs = ?, medical_hrs = ?, budget_hrs = ?
                    WHERE code = ?
                """, (available_hrs, annual_hrs, medical_hrs, budget_hrs, code))
            else:
                cursor.execute("""
                    UPDATE department_hrs_alloc 
                    SET available_hrs = ?, annual_hrs = ?, medical_hrs = ?
                    WHERE code = ?
                """, (available_hrs, annual_hrs, medical_hrs, code))

            message = "Record updated successfully!"

        else:
            # Insert new row, setting budget_hrs conditionally
            if budget_hrs is not None:
                cursor.execute("""
                    INSERT INTO department_hrs_alloc (code, role, available_hrs, annual_hrs, medical_hrs, budget_hrs)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (code, role, available_hrs, annual_hrs, medical_hrs, budget_hrs))
            else:
                cursor.execute("""
                    INSERT INTO department_hrs_alloc (code, role, available_hrs, annual_hrs, medical_hrs)
                    VALUES (?, ?, ?, ?, ?)
                """, (code, role, available_hrs, annual_hrs, medical_hrs))

            message = "New record added successfully!"

        db.commit()
        return jsonify({"success": True, "message": message})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/add_accommodation', methods=['POST'])
def add_accommodation():
    try:
        building = request.form['Building_Name']
        line1 = request.form['Address_Line1']
        line2 = request.form['Address_Line2']
        line3 = request.form['Address_Line3']
        contact = request.form['Contact']

        db = get_database()
        cursor = db.cursor()
        cursor.execute('''INSERT INTO Accommodation (Building_Name, Address_Line1, Address_Line2, Address_Line3, Contact)
            VALUES (?, ?, ?, ?, ?) ''', (building, line1, line2, line3, contact))
        db.commit()

        return jsonify({
            'success': True,
            'new_data': {
                'Building_Name': building,
                'Address_Line1': line1,
                'Address_Line2': line2,
                'Address_Line3': line3,
                'Contact': contact
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/delete_accommodation/<int:accommodation_id>', methods=['POST'])
def delete_accommodation(accommodation_id):
    try:

        db = get_database()
        cursor = db.cursor()
        cursor.execute("DELETE FROM Accommodation WHERE id = ?", (accommodation_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/admin_add_expense_type', methods=['POST'])
def admin_add_expense_type():
    try:
        expenses_type = request.form['Expenses_Type'].strip()
        expenses_value = request.form['Expenses_Value'].strip()

        db = get_database()
        cursor = db.cursor()

        # Check if type already exists
        print("....expenses_type.............",expenses_type)
        cursor.execute('SELECT id FROM expenses_values WHERE type = ?', (expenses_type,))
        existing = cursor.fetchone()
        print("....existing.............",existing)


        if existing:
            # Update existing row
            cursor.execute('''
                UPDATE expenses_values
                SET type_values = ?
                WHERE id = ?
            ''', (expenses_value, existing['id']))
            db.commit()
            updated_id = existing['id']
            return jsonify({
                'success': True,
                'updated': True,
                'new_data': {
                    'id': updated_id,
                    'type': expenses_type,
                    'type_values': expenses_value
                }
            })
        else:
            # Insert new row
            cursor.execute('''
                INSERT INTO expenses_values (type, type_values)
                VALUES (?, ?)
            ''', (expenses_type, expenses_value))
            db.commit()
            new_id = cursor.lastrowid
            return jsonify({
                'success': True,
                'updated': False,
                'new_data': {
                    'id': new_id,
                    'type': expenses_type,
                    'type_values': expenses_value
                }
            })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_expense_type/<int:id>', methods=['POST'])
def delete_expense_type(id):
    try:
        db = get_database()
        cursor = db.cursor()
        print("...........id........",id)

        cursor.execute("DELETE FROM expenses_values WHERE id = ?", (id,))
        db.commit()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


##--------------------------------------------------------PROJECTS------------------------------------------------------------------------------------------------------------------

def format_currency1(value):
    # Handle None value
    if value is None:
        value = 0.0  # Default to 0.0 if None
    
    # Round the value to two decimal places
    rounded_value = round(value, 2)
    
    # Format the value with commas as thousands separators
    formatted_value = "{:,.2f}".format(rounded_value)
    formatted_value1 = '$' + formatted_value
    return formatted_value1

@app.route('/get_proj_overview')
def get_proj_overview():
    project_id = request.args.get('projectId')
    db = get_database()
    cursor = db.cursor()
    from datetime import datetime, timedelta


    # --- Project Details ---
    prj_cur = cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    prj_details = dict(prj_cur) if prj_cur else {}

    # --- PR Details ---
    cursor.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC', (project_id,))
    pr_rows = cursor.fetchall()
    pr_columns = [desc[0] for desc in cursor.description]  # Capture column names once

    pr_data = []
    for row in pr_rows:
        pr_row = dict(zip(pr_columns, row))  # Safe from cursor overwrite
        pr_no = pr_row.get('PR_no')  # Use .get() for safety

        if pr_no:  # Proceed only if PR_no is valid
            cursor.execute("SELECT SUM(total), AVG(GST) FROM pr_items WHERE pr_number = ?", (pr_no,))
            total, gst_percent = cursor.fetchone()
            total = float(total or 0)
            gst_percent = float(gst_percent or 0)
            exchange_rate = float(pr_row.get('Exchange_rate') or 1.0)
            gst_amount = (total * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
            total_with_gst = total + gst_amount

            pr_row.update({
                'amount': round(total / exchange_rate, 2),
                'GST': round(gst_amount / exchange_rate, 2),
                'total': round(total_with_gst / exchange_rate, 2)
            })

        pr_data.append(pr_row)


    # --- PO Details ---
    cursor.execute('SELECT * FROM created_po WHERE project_id = ? ORDER BY id DESC', (project_id,))
    po_rows = cursor.fetchall()
    po_columns = [desc[0] for desc in cursor.description]  # Capture once

    po_data = []
    for row in po_rows:
        po_row = dict(zip(po_columns, row))
        PO_no = po_row.get('PO_no')

        if PO_no:
            cursor.execute("SELECT SUM(total), AVG(GST) FROM po_items WHERE PO_number = ?", (PO_no,))
            total, gst_percent = cursor.fetchone()
            total = float(total or 0)
            gst_percent = float(gst_percent or 0)
            exchange_rate = float(po_row.get('Exchange_rate') or 1.0)
            gst_amount = (total * gst_percent / 100) if gst_percent and gst_percent != 1 else 0
            total_with_gst = total + gst_amount

            po_row.update({
                'amount': round(total / exchange_rate, 2),
                'GST': round(gst_amount / exchange_rate, 2),
                'total': round(total_with_gst / exchange_rate, 2)
            })

        po_data.append(po_row)

    # --- Payment Details ---
    cursor.execute('SELECT * FROM payment_request WHERE proj_no = ? ORDER BY id DESC', (project_id,))
    pay_rows = cursor.fetchall()
    pay_columns = [desc[0] for desc in cursor.description]  # Capture once

    pay_data = []
    today = datetime.today().date()

    for row in pay_rows:
        pay = dict(zip(pay_columns, row))

        invoice_date_str = pay.get("Invoice_date")
        time_period = pay.get("time_period")
        terms = pay.get("Terms")
        due_date = None
        due_days = None

        if invoice_date_str:
            try:
                invoice_date = datetime.strptime(invoice_date_str, "%Y-%m-%d").date()
                if time_period in ['Days', 'Advance']:
                    terms_int = int(terms or 0)
                    due_date = invoice_date + timedelta(days=terms_int)
                    due_days = (due_date - today).days
                elif time_period == 'COD':
                    due_date = invoice_date
                    due_days = 0
            except Exception:
                due_date = None
                due_days = None

        pay.update({
            'due_date': due_date.strftime("%m/%d/%y") if due_date else "0/0/0",
            'due_days': due_days,
            'balence': float(pay.get("balence") or 0.0)
        })

        pay_data.append(pay)

    # --- DO Details ---
    cursor.execute('SELECT * FROM created_do WHERE proj_no = ? ORDER BY id DESC', (project_id,))
    do_data = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]

    # --- Claims (Claimed Items) ---
    cursor.execute("SELECT * FROM claimed_items WHERE projectid = ?", (project_id,))
    claim_items = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]

    # --- Project Budget (excluding dept codes 1000–1050) ---
    cursor.execute("""
        SELECT SUM(total) AS total_sum 
        FROM pmtable 
        WHERE project_id = ? AND CAST(department_code AS INTEGER) NOT BETWEEN 1000 AND 1050
    """, (project_id,))
    result = cursor.fetchone()
    prj_budget = result[0] or 0.0
    print(".......prj_budget...............",prj_budget)

    # --- Actual Project Spend (from manual_entry, includes exchange rate, discount, GST) ---
    cursor.execute("""
        SELECT SUM(((cost * COALESCE(Exchange_rate, 1)) * (1 - COALESCE(Discount, 0) / 100)) + COALESCE(gst_value, 0)) 
        AS total_sum 
        FROM manual_entry 
        WHERE project_id = ?
    """, (project_id,))
    result = cursor.fetchone()
    prj_actual = result[0] or 0.0



    # --- Calculate balances ---
    prj_balance = prj_budget - prj_actual
   

    # --- Prepare final structured list ---
    project_financials = [
        {
            "label": "Project Budget",
            "budget": round(prj_budget, 2),
            "actual": round(prj_actual, 2),
            "balance": round(prj_balance, 2)
        }
    ]


    # Get per-employee total cost
    cursor.execute("""  
        SELECT employeeID, SUM(total_cost) AS employee_total_cost
        FROM workingHours WHERE projectID = ? GROUP BY employeeID
        ORDER BY employee_total_cost DESC
    """, (project_id,))
    rows = cursor.fetchall()
    employee_costs = [dict(row) for row in rows]

    cursor.execute("""
        SELECT Supplier_Name, COUNT(*) AS po_count
        FROM created_po
        WHERE project_id = ?
        GROUP BY Supplier_Name
        ORDER BY po_count DESC
    """, (project_id,))
    rows = cursor.fetchall()
    supplier_counts = [dict(row) for row in rows]

    # Get actuals from manual_entry
    query_actuals = """
        SELECT department_code,
            SUM(
                CASE
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN total
                    ELSE ((total * 1.0 / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ) AS total_cost_after_conversion_and_discount
        FROM manual_entry
        WHERE project_id = ?
        GROUP BY department_code;
    """
    cursor.execute(query_actuals, (project_id,))
    
    department_totals = [
        {
            'department_code': row[0],
            'total_cost_after_conversion_and_discount': round(row[1] or 0.00, 2)
        }
        for row in cursor.fetchall()
    ]

    # Get budgets from pmtable excluding certain department codes
    excluded_department_codes = [
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        1000, 1001, 1002, 1003, 1004, 1005, 1006,
        1007, 1008, 1009, 1010, 1011, 1012, 1013,
        1014, 1015, 1016, 1017, 1018,1019, 1020 
    ]
    placeholders = ','.join('?' for _ in excluded_department_codes)

    query_budget = f"""
        SELECT department_code,
            SUM(total) AS total_cost
        FROM pmtable
        WHERE department_code NOT IN ({placeholders})
        AND project_id = ?
        GROUP BY department_code;
    """

    params = excluded_department_codes + [project_id]
    cursor.execute(query_budget, params)
    department_costs = [
        {
            'department_code': row[0],
            'total_cost': round(row[1] or 0.00, 2)
        }
        for row in cursor.fetchall()
    ]

    # Combine actuals and budgets by department_code
    combined_data = {}

    # Insert actuals
    for item in department_totals:
        dept_code = str(item['department_code'])  # Ensure dept_code is a string
        combined_data[dept_code] = {
            'department_code': dept_code,
            'actual': item['total_cost_after_conversion_and_discount'],
            'budget': 0.00
        }

    # Insert or update budgets
    for item in department_costs:
        dept_code = str(item['department_code'])  # Ensure dept_code is a string
        if dept_code in combined_data:
            combined_data[dept_code]['budget'] = item['total_cost']
        else:
            combined_data[dept_code] = {
                'department_code': dept_code,
                'actual': 0.00,
                'budget': item['total_cost']
            }


    # Convert to list
    final_combined_list = list(combined_data.values())

    manpower_summary = []

    # Step 1: Get all manpower cost center codes and names
    cursor.execute("SELECT code, expenses_name FROM cost_center")
    manpower_cost_centers = cursor.fetchall()

    man_power_total_budget = 0.0
    man_power_total_actuals = 0.0

    for code, name in manpower_cost_centers:
        # Step 2: Get total budget (from pmtable) for the given project and code
        cursor.execute("""
            SELECT SUM(total)
            FROM pmtable
            WHERE project_id = ?
            AND department_code = ?
        """, (project_id, code))
        budget = cursor.fetchone()[0] or 0.00

        # Step 3: Get total actual (from workingHours) for the same code (as departmentID)
        cursor.execute("""
            SELECT SUM(total_cost)
            FROM workingHours
            WHERE projectID = ?
            AND departmentID = ?
        """, (project_id, code))
        actual = cursor.fetchone()[0] or 0.00

        # Step 4: Build the dictionary for this code
        manpower_summary.append({
            'code': code,
            'name': name,
            'budget': round(budget, 2),
            'actuals': round(actual, 2)
        })
        man_power_total_budget += budget
        man_power_total_actuals += actual

    
    overall_manpower_summary = [{
    'label': 'Manpower Budget',
    'budget': round(man_power_total_budget, 2),
    'actuals': round(man_power_total_actuals, 2),
    'balance': round(man_power_total_budget - man_power_total_actuals, 2)
    }]

    project_financials.append(overall_manpower_summary[0])


    # Define department code categories
    material_codes = {'2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009'}
    subcontract_codes = {'3001', '3002', '3003', '3004', '3005', '3006', '3007', '3008', '3009', '3010'}

    # Initialize accumulators
    material_budget = material_actual = 0.0
    subcontract_budget = subcontract_actual = 0.0
    others_budget = others_actual = 0.0

    # Loop through combined list
    for item in final_combined_list:
        dept_code = item['department_code']
        budget = item.get('budget', 0.0) or 0.0
        actual = item.get('actual', 0.0) or 0.0

        if dept_code in material_codes:
            material_budget += budget
            material_actual += actual
        elif dept_code in subcontract_codes:
            subcontract_budget += budget
            subcontract_actual += actual
        else:
            others_budget += budget
            others_actual += actual

    # Prepare summary
    category_summary = [
        {
            "label": "Mtrl",
            "budget": round(material_budget, 2),
            "actual": round(material_actual, 2),
            "balance": round(material_budget - material_actual, 2)
        },
        {
            "label": "SubCon",
            "budget": round(subcontract_budget, 2),
            "actual": round(subcontract_actual, 2),
            "balance": round(subcontract_budget - subcontract_actual, 2)
        },
        {
            "label": "Others",
            "budget": round(others_budget, 2),
            "actual": round(others_actual, 2),
            "balance": round(others_budget - others_actual, 2)
        }
    ]


    # --- Response ---
    return jsonify({
        'success': True,
        'project_details': dict(prj_details) if prj_details else {},
        'pr_data': pr_data,
        'po_data': po_data,
        'payment_data': pay_data,
        'do_data': do_data,
        'claimed_items': claim_items,
        'project_financials': project_financials,
        'employee_costs': employee_costs,
        'supplier_counts': supplier_counts,
        'final_combined_list':final_combined_list,
        'manpower_summary' : manpower_summary,
        'category_summary':category_summary
    })

from datetime import datetime
@app.route('/projects')
@login_required
def projects():
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute('SELECT DISTINCT strftime("%Y", start_time) as year FROM projects WHERE start_time IS NOT NULL ORDER BY year DESC')
    some_condition = True
    user_access = get_employee_access_control(user['name'])

    # if department_code == 1000 or user['name'] == 'soodesh' or user['name'] == 'N.Mahendran':
    if user_access and user_access.get("toggleAllProjects") == 'On':

        pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value, type, project_members FROM projects WHERE status != "Closed" ORDER BY id DESC')

    elif user_access and user_access.get("toggleInvolvedProjects") == 'On':
        pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value, type, project_members FROM projects WHERE (pm = ? OR project_members LIKE ?) AND status != "Closed" ORDER BY id DESC', (user['name'], '%' + user['name'] + '%'))

    elif some_condition:
        pro_cur = db.execute('SELECT * FROM projects WHERE project_members LIKE ? AND status != "Closed"', ('%' + user['name'] + '%',))

    allpro = []

    for pro_row in pro_cur.fetchall():

        pro_dict = dict(pro_row)
        project_id = pro_dict['id']  # Assuming the primary key column name is 'id'

        if isinstance(pro_dict['po_value'], int):
            po_value = pro_dict['po_value']
        
        else:
            po_value_str = str(pro_dict['po_value']).replace(',', '')
            try:
                po_value = int(float(po_value_str))
            except ValueError:
                po_value = 0  # or set a default value
        
        if po_value > 0:
            merged_df = calculate_working_hours(project_id)
            cost_df = calculate_project_cost(project_id)
            ranges = [(2001, 2008), (3001, 3010), (4001, 4004)]
            cost_df['department_code'] = pd.to_numeric(cost_df['department_code'], errors='coerce')
            cost_df['department_code'] = cost_df['department_code'].astype('Int64')
            dfs = {}
            for range_ in ranges:
                start, end = range_
                key = f'df_{start}_{end}'
                dfs[key] = cost_df[cost_df['department_code'].between(start, end)]

            df_2001_2008 = dfs['df_2001_2008']
            df_3001_3010 = dfs['df_3001_3010']
            df_4001_4004 = dfs['df_4001_4004']

            sum_allocated_hours_1000 = merged_df['allocated_hours'].sum()
            sum_hours_worked_1000 = merged_df['hours_worked'].sum()

            sum_allocated_hours_2000 = df_2001_2008['allocated_hours'].sum()
            sum_hours_worked_2000 = df_2001_2008['hours_worked'].sum()

            sum_allocated_hours_3000 = df_3001_3010['allocated_hours'].sum()
            sum_hours_worked_3000 = df_3001_3010['hours_worked'].sum()

            sum_allocated_hours_4000 = df_4001_4004['allocated_hours'].sum()
            sum_hours_worked_4000 = df_4001_4004['hours_worked'].sum()

            new_row_1000 = {'department_code': 1000,'Description':'Resource', 'allocated_hours': sum_allocated_hours_1000, 'hours_worked': sum_hours_worked_1000}
            new_row_3000 = {'department_code': 3000,'Description':'Sub Contract','allocated_hours': sum_allocated_hours_3000, 'hours_worked': sum_hours_worked_3000}
            new_row_2000 = {'department_code': 2000,'Description':'Material','allocated_hours': sum_allocated_hours_2000, 'hours_worked': sum_hours_worked_2000}
            new_row_4000 = {'department_code': 4000,'Description':'Others','allocated_hours': sum_allocated_hours_4000, 'hours_worked': sum_hours_worked_4000}
            
            summary_table = pd.DataFrame(columns=['department_code','Description', 'allocated_hours', 'hours_worked'])
            summary_table = pd.DataFrame([new_row_1000,new_row_2000,new_row_3000, new_row_4000], columns=['department_code', 'Description','allocated_hours', 'hours_worked'])
            summary_table['department_code'] = summary_table['department_code'].astype(int)
            sumA = summary_table['allocated_hours'].sum()
            sumH = summary_table['hours_worked'].sum()
            margin = (po_value - sumH) / po_value * 100 
            rounded_margin = round(margin, 2)
            pro_dict['margin'] = rounded_margin
        
        else:
            pro_dict['margin'] = 0
        
        working_hours_df = calculate_working_hours(project_id)  # Call the function to get working hours data
        working_hours_df['allocated_hours'] = pd.to_numeric(working_hours_df['allocated_hours'], errors='coerce')
        allocated_hours = working_hours_df['allocated_hours'].sum()
        hours_worked = working_hours_df['hours_worked'].sum()

        if allocated_hours > 0:
            percentage = (hours_worked / allocated_hours) * 100
            pro_dict['resource'] = round(percentage)  # Round the percentage value to a whole number
        else:
            pro_dict['resource'] = 0

        material_df = calculate_material_cost(project_id)  # Call the function to get working hours data
        material_df['allocated_hours'] = pd.to_numeric(material_df['allocated_hours'], errors='coerce')
        allocated_hours = material_df['allocated_hours'].sum()
        hours_worked = material_df['hours_worked'].sum()
        if allocated_hours > 0:
            percentage = (hours_worked / allocated_hours) * 100
            pro_dict['material'] = round(percentage)  # Round the percentage value to a whole number
        else:
            pro_dict['material'] = 0

        sub_contract_df = calculate_sub_contract_cost(project_id)  # Call the function to get working hours data
        sub_contract_df['allocated_hours'] = pd.to_numeric(sub_contract_df['allocated_hours'], errors='coerce')
        allocated_hours = sub_contract_df['allocated_hours'].sum()
        hours_worked = sub_contract_df['hours_worked'].sum()
        if allocated_hours > 0:
            percentage = (hours_worked / allocated_hours) * 100
            pro_dict['sub_contract'] = round(percentage)  # Round the percentage value to a whole number
        else:
            pro_dict['sub_contract'] = 0

        others_df = calculate_others_cost(project_id)  # Call the function to get working hours data
        others_df['allocated_hours'] = pd.to_numeric(others_df['allocated_hours'], errors='coerce')
        allocated_hours = others_df['allocated_hours'].sum()
        hours_worked = others_df['hours_worked'].sum()
        if allocated_hours > 0:
            percentage = (hours_worked / allocated_hours) * 100
            pro_dict['others'] = round(percentage)  # Round the percentage value to a whole number
        else:
            pro_dict['others'] = 0
        # print(".pro_dict..........",pro_dict)
        alerts = project_alerts(project_id)
        # print("................",alerts)
        pro_dict['alerts'] = alerts  # Add alerts as a key in the dictionary
        # print("....pro_dict............",pro_dict)
        allpro.append(pro_dict)

    
    return render_template('admin_templates/projects/index.html',is_pm=is_pm,department_code=department_code, user=user, user_access=user_access,allpro=allpro)
     
@app.route('/get_project_budget/<int:project_id>', methods=['GET'])
def get_project_budget(project_id):
    # print("............project_id..........",project_id)
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT department_code, total FROM pmtable WHERE project_id = ?", (project_id,))
    data = cursor.fetchall()
    project_data = {str(department_code): total for department_code, total in data}
    # print(".......project_data............",project_data)
    return jsonify(project_data)

import locale
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
@app.route('/admin_project_edit/<int:proid>', methods=['GET', 'POST'])
@login_required
def admin_project_edit(proid):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # print("............admin_project_edit...............\n")
    user = get_current_user()
    db = get_database()
    is_pm = is_pm_for_project(user['name'])
    username = user['name']
    department_code = get_department_code_by_username(username)
    single_pro = fetchone_for_edit(proid)
    project_cur = db.execute('SELECT *, strftime("%Y-%m-%d", start_time) AS formatted_start_time, strftime("%Y-%m-%d", end_time) AS formatted_end_time FROM projects WHERE id = ?', [proid])
    project_details = project_cur.fetchone()
    usernames = get_all_usernames()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    department_data2 = {} 
    cursor.execute("SELECT code, expenses_name FROM cost_center")
    rows = cursor.fetchall()
    # Store the results in a dictionary
    cost_center_dict = {row[0]: row[1] for row in rows}
    # print("................cost_center_dict......\n",cost_center_dict)
    user_access = get_employee_access_control(user['name'])
    
    if project_details is not None:
        locale.setlocale(locale.LC_ALL, '')
        user = get_current_user()
        db = get_database()
        is_pm1 = is_pm_for_project(user['name'])
        username1 = user['name']
        department_code1 = get_department_code_by_username(username)
        single_pro = fetchone_for_edit(proid)
        project_cur = db.execute('SELECT *, strftime("%Y-%m-%d", start_time) AS formatted_start_time, strftime("%Y-%m-%d", end_time) AS formatted_end_time FROM projects WHERE id = ?', [proid])
        project_details = project_cur.fetchone()
        usernames1 = get_all_usernames()
        cursor = db.cursor()
        cursor.execute('SELECT username FROM admin_user')
        usernames = [row[0] for row in cursor.fetchall()]
        department_data2 = {}

        if request.method == 'POST':
            employee_username = request.form.get('employee_username')
            department_code = request.form.get('department_code')
            hours_allocated = request.form.get('hours_allocated')
            db.execute("INSERT INTO pmtable (project_id, username, department_code, hours) VALUES (?, ?, ?, ?)", [project_details['id'], employee_username, department_code, hours_allocated])
            db.commit()

        from collections import defaultdict

        # Fetch data from database
        pmtable_cur = db.execute('SELECT * FROM pmtable WHERE project_id = ?', [project_details['id']])
        from_pmtable_rows = pmtable_cur.fetchall()
        working_hours_cur = db.execute("SELECT departmentID, SUM(total_cost) AS hours_worked FROM workingHours WHERE projectID = ? GROUP BY departmentID", [project_details['id']])
        from_working_hours = working_hours_cur.fetchall()
        cost_cur = db.execute("SELECT department_code, SUM(total) AS hours_worked FROM manual_entry WHERE project_id = ? GROUP BY department_code", [project_details['id']])
        cost_hours = cost_cur.fetchall()

        # Use defaultdict to simplify initialization
        department_data = defaultdict(lambda: [0.0, 0.0, 0.0])  # hours, added_hours, total
        department_hours = defaultdict(float)  # actual hours worked (from workingHours and cost_hours)

        # Process data from pmtable
        for project_id, username, department_code, hours, added_hours, total in from_pmtable_rows:
            try:
                department_code = int(department_code)
                department_data[department_code][0] += hours
                department_data[department_code][1] += added_hours
                department_data[department_code][2] += total
            except ValueError:
                print(f"Invalid department_code: {department_code}")  # Error logging

        # Process data from workingHours and cost_hours
        for department_id, hours_worked in from_working_hours + cost_hours:
            try:
                department_id = int(department_id)
                if department_id not in department_hours:
                    department_hours[department_id] = 0.0

                department_hours[department_id] += hours_worked or 0.0

                # department_hours[department_id] += hours_worked
            except ValueError:
                print(f"Invalid department_id: {department_id}")  # Error logging

        # Merge department_data and department_hours into department_data2
        department_data2 = {dept: values + [department_hours.get(dept, 0.0)] for dept, values in department_data.items()}

        # Ensure all department_hours data is included
        for dept_id, hours_worked in department_hours.items():
            if dept_id not in department_data2:
                department_data2[dept_id] = [0.0, 0.0, 0.0, hours_worked]

        # Calculate total minus actual (total - actual hours worked)
        for dept_id in department_data2:
            department_data2[dept_id].append(department_data2[dept_id][2] - department_data2[dept_id][3])

        # print(".........pmtable_rows..........", department_data2)

        # Define range totals with dictionary comprehension
        range_totals = {key: [0.0] * 5 for key in ["1000-1999", "2000-4999 & 500-599"]}

        # Aggregate values into range_totals
        for dept_id, values in department_data2.items():
            if (1000 <= dept_id <= 1999) or (10 <= dept_id <= 100):
                key = "1000-1999"
            elif (2000 <= dept_id <= 2999) or (3000 <= dept_id <= 3999) or (4000 <= dept_id <= 4999) or (500 <= dept_id <= 599):
                key = "2000-4999 & 500-599"
            else:
                continue  # Skip if department doesn't match any range

            # Add values to the corresponding range bucket
            for i in range(5):
                range_totals[key][i] += values[i]

            # Fetch relevant fields for the given project_id
        cursor.execute("""
            SELECT payment_status, do_staus, status
            FROM created_po
            WHERE project_id = ?
        """, (project_id,))
        rows = cursor.fetchall()

        # Check if all values across all rows are "Closed"
        all_closed = all(
            row["payment_status"] == "Closed" and
            row["do_staus"] == "Closed" and
            row["status"] == "Closed"
            for row in rows
        )
        prj_close_stat = "Can Close" if all_closed else "Can't Close"
        print("...............prj_close_stat......",prj_close_stat)

        return render_template('admin_templates/projects/admin_project_edit.html',user_access=user_access, user=user, single_pro = single_pro,project_details=project_details,
                               department_code=department_code1, is_pm = is_pm,usernames=usernames, pmtable_rows=department_data2,range_totals=range_totals,
                               prj_close_stat=prj_close_stat)
    
    else:
        return render_template('admin_templates/projects/admin_project_edit.html',user_access =user_access, user=user, range_totals=range_totals,
                               single_pro = single_pro,project_details=project_details,department_code=department_code, is_pm = is_pm,usernames=usernames, pmtable_rows=department_data2)

import pandas as pd
def calculate_working_hours(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016]

    # Prepare the placeholders for the IN clause in the SQL query
    placeholders = ', '.join(['?'] * len(department_codes))

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = f"SELECT department_code, total FROM pmtable WHERE project_id = ? AND department_code IN ({placeholders})"
    cursor.execute(pm_query, (project_id,) + tuple(department_codes))
    pm_data = cursor.fetchall()

    # Query to get worked hours from workingHours table
    wh_query = "SELECT departmentID, SUM(hoursWorked) AS hours_worked FROM workingHours WHERE projectID = ? GROUP BY departmentID"
    cursor.execute(wh_query, (project_id,))
    wh_data = cursor.fetchall()

    # Create DataFrames from the query results
    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    wh_df = pd.DataFrame(wh_data, columns=['departmentID', 'hours_worked'])

    # Ensure the department_code and departmentID columns are of the same type
    pm_df['department_code'] = pm_df['department_code'].astype(str)
    wh_df['departmentID'] = wh_df['departmentID'].astype(str)

    # Create a full list of department codes with zero allocated hours
    all_depts_df = pd.DataFrame({'department_code': [str(code) for code in department_codes], 'allocated_hours': [0.0] * len(department_codes)})

    # Merge all_depts_df with pm_df to ensure all department codes are included
    all_pm_df = all_depts_df.merge(pm_df, on='department_code', how='left')
    all_pm_df['allocated_hours'] = all_pm_df['allocated_hours_y'].combine_first(all_pm_df['allocated_hours_x'])
    all_pm_df = all_pm_df[['department_code', 'allocated_hours']]

    # Merge the DataFrames and fill NaN values
    merged_df = all_pm_df.merge(wh_df, left_on='department_code', right_on='departmentID', how='left')
    merged_df['hours_worked'].fillna(0.0, inplace=True)
    merged_df = merged_df.drop('departmentID', axis=1)

    return merged_df

def calculate_project_cost(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of all department codes to include in the query
    all_department_codes = [2000,2001, 2002, 2003, 2004, 2005,2006,2007,2008,2009,
                            3000,3001, 3002, 3003, 3004, 3005, 3006,3007,3008,3009,3010,
                            4000,4001, 4002, 4003, 4004,
                            501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517,518,519,520 ]

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = "SELECT department_code, total FROM pmtable WHERE project_id = ?"
    cursor.execute(pm_query, (project_id,))
    pm_data = cursor.fetchall()

    cost_query = """
        SELECT 
            department_code, 
            SUM(
                CASE 
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                    ELSE ((total / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ) AS hours_worked
        FROM manual_entry  
        WHERE project_id = ?
        GROUP BY department_code
    """

    cursor.execute(cost_query, (project_id,))
    cost_data = cursor.fetchall()


    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    cost_df = pd.DataFrame(cost_data, columns=['department_code', 'hours_worked'])

    # Ensure both 'department_code' columns have the same data type (int32)
    pm_df['department_code'] = pm_df['department_code'].astype('int32')
    cost_df['department_code'] = cost_df['department_code'].astype('int32')
    # pm_df['department_code'] = pd.to_numeric(pm_df['department_code'], errors='coerce')
    # cost_df['department_code'] = pd.to_numeric(cost_df['department_code'], errors='coerce')


    # Create a DataFrame with all department codes and merge with pm_df to ensure all codes are included
    all_pm_df = pd.DataFrame({'department_code': all_department_codes})
    pm_df = pd.merge(all_pm_df, pm_df, on='department_code', how='left')
    pm_df['allocated_hours'].fillna(0.0, inplace=True)
    # Merge the DataFrames using an outer join to include all department codes
    merged_df = pd.merge(pm_df, cost_df, on='department_code', how='outer')
    merged_df.fillna(0, inplace=True)  # Fill NaN values with 0

    # print(".......data from .calculate_project_cost function............\n",merged_df)

    return merged_df

def calculate_material_cost(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [2001,2002,2003,2004,2005,2006,2007,2008,2009]

    # Prepare the placeholders for the IN clause in the SQL query
    placeholders = ', '.join(['?'] * len(department_codes))

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = f"SELECT department_code, total FROM pmtable WHERE project_id = ? AND department_code IN ({placeholders})"
    cursor.execute(pm_query, (project_id,) + tuple(department_codes))
    pm_data = cursor.fetchall()



    cost_cur = db.execute("""
        SELECT 
            department_code, 
            SUM(
                CASE 
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                    ELSE ((total / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ) AS hours_worked
        FROM manual_entry 
        WHERE project_id = ?
        GROUP BY department_code
    """, [project_id])

    cost_hours = cost_cur.fetchall()

    

    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    cost_hours = pd.DataFrame(cost_hours, columns=['departmentID', 'hours_worked'])
    cost_hours['departmentID'] = cost_hours['departmentID'].astype(str)

    # Merge the DataFrames and fill NaN values in 'departmentID' with 'department_code'
    merged_df = pm_df.merge(cost_hours, left_on='department_code', right_on='departmentID', how='outer')
    merged_df['departmentID'].fillna(merged_df['department_code'], inplace=True)
    merged_df = merged_df.drop('departmentID', axis=1)
    merged_df['hours_worked'].fillna(0.0, inplace=True)
    merged_df = merged_df.dropna(subset=['department_code'])
    return merged_df

def calculate_sub_contract_cost(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [3001,3002,3003,3004,3005,3006,3007,3008,3009,3010]

    # Prepare the placeholders for the IN clause in the SQL query
    placeholders = ', '.join(['?'] * len(department_codes))

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = f"SELECT department_code, total FROM pmtable WHERE project_id = ? AND department_code IN ({placeholders})"
    cursor.execute(pm_query, (project_id,) + tuple(department_codes))
    pm_data = cursor.fetchall()

    cost_cur = db.execute("""
        SELECT 
            department_code, 
            SUM(
                CASE 
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                    ELSE ((total / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ) AS hours_worked
        FROM manual_entry 
        WHERE project_id = ?
        GROUP BY department_code
    """, [project_id])

    cost_hours = cost_cur.fetchall()

    cursor.close()

    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    cost_hours = pd.DataFrame(cost_hours, columns=['departmentID', 'hours_worked'])
    cost_hours['departmentID'] = cost_hours['departmentID'].astype(str)

    # Merge the DataFrames and fill NaN values in 'departmentID' with 'department_code'
    merged_df = pm_df.merge(cost_hours, left_on='department_code', right_on='departmentID', how='outer')
    merged_df['departmentID'].fillna(merged_df['department_code'], inplace=True)
    merged_df = merged_df.drop('departmentID', axis=1)
    merged_df['hours_worked'].fillna(0.0, inplace=True)
    merged_df = merged_df.dropna(subset=['department_code'])
    return merged_df

def calculate_others_cost(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [4001,4002,4003,4004]

    # Prepare the placeholders for the IN clause in the SQL query
    placeholders = ', '.join(['?'] * len(department_codes))

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = f"SELECT department_code, total FROM pmtable WHERE project_id = ? AND department_code IN ({placeholders})"
    cursor.execute(pm_query, (project_id,) + tuple(department_codes))
    pm_data = cursor.fetchall()

    cost_cur = db.execute("SELECT department_code, total AS hours_worked FROM manual_entry WHERE project_id = ? GROUP BY department_code",[project_id])
    cost_hours = cost_cur.fetchall()

    cursor.close()

    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    cost_hours = pd.DataFrame(cost_hours, columns=['departmentID', 'hours_worked'])
    cost_hours['departmentID'] = cost_hours['departmentID'].astype(str)

    # Merge the DataFrames and fill NaN values in 'departmentID' with 'department_code'
    merged_df = pm_df.merge(cost_hours, left_on='department_code', right_on='departmentID', how='outer')
    merged_df['departmentID'].fillna(merged_df['department_code'], inplace=True)
    merged_df = merged_df.drop('departmentID', axis=1)
    merged_df['hours_worked'].fillna(0.0, inplace=True)
    merged_df = merged_df.dropna(subset=['department_code'])
    return merged_df

import sqlite3
import json

import sqlite3
import pandas as pd
from datetime import datetime

# Function to calculate analytics for a given project ID
def get_project_analytics(project_id):
    # Connect to SQLite database
    db = get_database()  # Assume this function is fetching the DB connection
    cursor = db.cursor()
    
    # Query to fetch working hours data
    query = "SELECT * FROM workingHours"
    
    # Reading the data into a dataframe
    df = pd.read_sql_query(query, db)  # Pass the connection, not the cursor

    # Filter data for the given projectID
    project_df = df[df['projectID'] == project_id]

    # Dictionary to store results
    analytics_results = {}

    # --- 1. Employee Productivity ---
    analytics_results['employee_productivity'] = {}

    # Average working hours per day
    avg_hours_per_employee = project_df.groupby('employeeID')['hoursWorked'].mean().reset_index()
    avg_hours_per_employee.columns = ['employeeID', 'avg_hours_per_day']
    analytics_results['employee_productivity']['avg_hours_per_day'] = avg_hours_per_employee.to_dict(orient='records')

    # Overtime trends
    overtime = project_df.groupby('employeeID')[['overtime_1_5', 'overtime_2_0']].sum().reset_index()
    analytics_results['employee_productivity']['overtime_trends'] = overtime.to_dict(orient='records')

    # Utilization rate
    project_df['utilization_rate'] = (project_df['hoursWorked'] / 8).clip(upper=1)  # Clip the rate to a max of 1
    analytics_results['employee_productivity']['utilization_rate'] = project_df[['employeeID', 'utilization_rate']].to_dict(orient='records')

    # --- 2. Project Analysis ---
    analytics_results['project_analysis'] = {}

    # Project effort allocation
    project_effort = project_df.groupby('projectID')['totalhours'].sum().reset_index()
    analytics_results['project_analysis']['project_effort'] = project_effort.to_dict(orient='records')

    # Project costs
    project_costs = project_df.groupby(['projectID', 'client'])['total_cost'].sum().reset_index()
    analytics_results['project_analysis']['project_costs'] = project_costs.to_dict(orient='records')

    # Project overtime burden
    project_overtime = project_df.groupby('projectID')[['overtime_1_5', 'overtime_2_0']].sum().reset_index()
    analytics_results['project_analysis']['project_overtime'] = project_overtime.to_dict(orient='records')

    # --- 3. Department Performance ---
    analytics_results['department_performance'] = {}

    # Departmental hours
    dept_hours = project_df.groupby('departmentID')['hoursWorked'].sum().reset_index()
    analytics_results['department_performance']['department_hours'] = dept_hours.to_dict(orient='records')

    # Department overtime
    dept_overtime = project_df.groupby('departmentID')[['overtime_1_5', 'overtime_2_0']].sum().reset_index()
    analytics_results['department_performance']['department_overtime'] = dept_overtime.to_dict(orient='records')

    # --- 4. Time-Based Trends ---
    analytics_results['time_based_trends'] = {}

    # Daily, weekly, and monthly hours
    project_df['month'] = pd.to_datetime(project_df['workingDate']).dt.to_period('M')
    monthly_hours = project_df.groupby('month')['hoursWorked'].sum().reset_index()
    analytics_results['time_based_trends']['monthly_hours'] = monthly_hours.to_dict(orient='records')

    # Peak work periods
    peak_periods = project_df.groupby('workingDate')['hoursWorked'].sum().reset_index()
    analytics_results['time_based_trends']['peak_work_periods'] = peak_periods.to_dict(orient='records')

    # --- 5. Client Insights ---
    analytics_results['client_insights'] = {}

    # Client profitability
    client_profitability = project_df.groupby('client')[['totalhours', 'total_cost']].sum().reset_index()
    analytics_results['client_insights']['client_profitability'] = client_profitability.to_dict(orient='records')

    # Client workload distribution
    client_workload = project_df.groupby('client')['projectID'].nunique().reset_index()
    client_workload.columns = ['client', 'project_count']
    analytics_results['client_insights']['client_workload_distribution'] = client_workload.to_dict(orient='records')

    # --- 6. Compliance Monitoring ---
    analytics_results['compliance_monitoring'] = {}

    # Overtime regulations
    overtime_regulations = project_df[project_df['overtime_1_5'] + project_df['overtime_2_0'] > 10]  # Adjust threshold as needed
    analytics_results['compliance_monitoring']['overtime_regulations'] = overtime_regulations.to_dict(orient='records')

    # Work-hour violations
    work_hour_violations = project_df[(project_df['hoursWorked'] < 4) | (project_df['hoursWorked'] > 12)]  # Example thresholds
    analytics_results['compliance_monitoring']['work_hour_violations'] = work_hour_violations.to_dict(orient='records')

    # --- 7. Cost Management ---
    analytics_results['cost_management'] = {}

    # Total labor cost
    total_cost = project_df['total_cost'].sum()
    analytics_results['cost_management']['total_labor_cost'] = total_cost

    # Overtime costs
    overtime_costs = project_df[['overtime_1_5', 'overtime_2_0']].sum().to_dict()
    analytics_results['cost_management']['overtime_costs'] = overtime_costs

    # --- 8. Comparative Analytics ---
    analytics_results['comparative_analytics'] = {}

    # Employee comparisons
    employee_comparison = project_df.groupby('employeeID')[['hoursWorked', 'overtime_1_5', 'overtime_2_0', 'total_cost']].sum().reset_index()
    analytics_results['comparative_analytics']['employee_comparisons'] = employee_comparison.to_dict(orient='records')

    # Department/project comparisons
    department_comparison = dept_hours.merge(dept_overtime, on='departmentID')
    analytics_results['comparative_analytics']['department_comparisons'] = department_comparison.to_dict(orient='records')

    # --- 9. Forecasting and Planning ---
    analytics_results['forecasting_and_planning'] = {}

    # Placeholder for workload forecasting
    workload_forecast = monthly_hours  # Example for future input to forecasting
    analytics_results['forecasting_and_planning']['workload_forecast'] = workload_forecast.to_dict(orient='records')

    # --- 10. Data Quality and Anomalies ---
    analytics_results['data_quality'] = {}

    # Check for missing or unusual data
    anomalies = project_df[(project_df['hoursWorked'] <= 0) | (project_df['totalhours'] != project_df['hoursWorked'] + project_df['overtime_1_5'] + project_df['overtime_2_0'])]
    analytics_results['data_quality']['anomalies'] = anomalies.to_dict(orient='records')

    return analytics_results

def get_department_cost_summary(project_id):
    try:
        db = get_database()  # Function to get the database connection
        cursor = db.cursor() 
        
        query_pmtable = """ SELECT department_code, SUM(total) AS department_total FROM pmtable WHERE project_id = ?  GROUP BY department_code;"""
        cursor.execute(query_pmtable, (project_id,))
        department_totals = cursor.fetchall()

        # Print the values on the terminal
        print("Department Totals:")
        for department_code, department_total in department_totals:
            # print(".........department_code..........",type(department_code))
            if department_code == '1001':
                print(f"Department Code: {department_code}, Total Hours: {department_total}")

        department_codes = [row[0] for row in department_totals]

        # You can now use department_codes as a list containing all department codes
        # print(department_codes)

        query = """ SELECT wh.departmentID, e.username, wh.totalhours, wh.total_cost, e.rate_per_hour FROM workingHours wh JOIN 
                              admin_user e ON wh.employeeID = e.username WHERE  wh.projectID = ?; """
        cursor.execute(query, (project_id,))
        results = cursor.fetchall()
        department_cost_summary = {}
        # print("....department_totals..........",department_totals)
        # Store department totals in a dictionary
        department_totals_dict = {row[0]: row[1] for row in department_totals}
        # print("....department_totals_dict..........",department_totals_dict)
        # Fetch hourly rate from the cost_center table based on department code
        query_cost_center = """SELECT code, hourly_rate FROM cost_center; """
        cursor.execute(query_cost_center)
        cost_center_data = cursor.fetchall()
        # print("..before..department_totals_dict..........\n",cost_center_data)

        # Store the hourly rate for each department code in a dictionary
        hourly_rate_dict = {row[0]: row[1] if row[1] is not None else 0.0 for row in cost_center_data}
        # print("...after.department_totals_dict..........\n",hourly_rate_dict)

        for department_code in department_codes:
            if department_code not in department_cost_summary:
                department_cost_summary[department_code] = {"total_adjusted_cost": 0.0,"employees": [{"employee_name": "None", "total_hours": 0.0, "total_cost": 0.0, "adjusted_cost": 0.0}],"budget_for_hours": 0.0}
        # Process the working hours and cost summary
        for row in results:
            
            department_id = row[0]
            total_hours = row[2]
            total_cost = row[3]
            rate_per_hour = row[4]
            # print("....department_id.....total_hours....total_cost..rate_per_hour...",department_id,total_hours,total_cost,rate_per_hour)
            # Ensure these are treated as floats (or 0.0 if None)
            total_cost = float(row[3]) if row[3] else 0.0
            rate_per_hour = float(row[4]) if row[4] else 0.0

            # Calculate the adjusted cost for each entry (rounded to 2 decimal places)
            adjusted_cost = round(rate_per_hour * total_cost, 2)
            # print("..............department_id......rate_per_hour....",department_id,rate_per_hour)
            
            if department_id not in department_cost_summary:
                # print("..............if department_id not in department_cost_summary:...r....",department_id)
                department_cost_summary[department_id] = { "total_adjusted_cost": 0.0, "employees": [], "budget_for_hours": 0.0 }
            
            department_cost_summary[department_id]["total_adjusted_cost"] = round(department_cost_summary[department_id]["total_adjusted_cost"] + adjusted_cost, 2)
            department_cost_summary[department_id]["employees"].append({ "total_hours": total_hours, "total_cost": total_cost, "adjusted_cost": adjusted_cost })

        # print("........department_cost_summary........\n",department_cost_summary)
        # Now, calculate the 'budget_for_hours' based on department totals and hourly rates
        for department_id in department_cost_summary:
            department_code = str(department_id)
            
            # If the department code is in both department_totals_dict and hourly_rate_dict
            if department_code in department_totals_dict and department_code in hourly_rate_dict:
                department_total = department_totals_dict[department_code]
                hourly_rate = hourly_rate_dict[department_code]
                budget_for_hours = round(department_total * hourly_rate, 2)
                department_cost_summary[department_id]["budget_for_hours"] = budget_for_hours
            else:
                # Set to zero if the department code is missing in either dictionary
                department_cost_summary[department_id]["budget_for_hours"] = 0.0

        # Simplified summary
        simplified_summary = {}
        for department_id in department_cost_summary:
            department_code = str(department_id)
            simplified_summary[department_code] = { "total_adjusted_cost": department_cost_summary[department_id]["total_adjusted_cost"], "budget_for_hours": department_cost_summary[department_id]["budget_for_hours"]}

        cursor.execute("SELECT code FROM cost_center")
        cost_center_codes = [row[0] for row in cursor.fetchall()]

            # If no data exists, set missing codes to zero
        for code in cost_center_codes:
            if code not in simplified_summary:
                simplified_summary[code] = { "total_adjusted_cost": 0.0, "budget_for_hours": 0.0}

        # Combine detailed and simplified summaries into one response
        full_summary = { "department_cost_summary": department_cost_summary, "simplified_summary": simplified_summary}
        # print("....full_summary......",full_summary)

        return full_summary  # Return as a dictionary, not JSON

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

import plotly.graph_objects as go

@app.route('/graph/<int:project_id>')
@login_required
def generate_graph(project_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    def categorize_dept(dept_code_str):
        try:
            code = int(dept_code_str)
        except:
            return "Others"
        if 1000 <= code <= 1999:
            return "Resources"
        elif 2000 <= code <= 2999:
            return "Material"
        elif 3000 <= code <= 3999:
            return "Sub Contract"
        elif 4000 <= code <= 4999:
            return "Site"
        else:
            return "Others"

    db = get_database()
    cursor = db.cursor()
    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    user_access = get_employee_access_control(user['name'])
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()

    # Budget per department (total * hourly_rate)
    cursor.execute("""
        SELECT p.department_code, 
               COALESCE(SUM(p.total), 0) AS sum_total, 
               COALESCE(c.hourly_rate, 1) AS hourly_rate
        FROM pmtable p
        LEFT JOIN cost_center c ON p.department_code = c.code
        WHERE p.project_id = ?
        GROUP BY p.department_code
    """, (project_id,))
    budget_rows = cursor.fetchall()

    budget_per_department = {}
    for dept_code, sum_total, hourly_rate in budget_rows:
        dept_code_str = str(dept_code)
        budget_per_department[dept_code_str] = round(sum_total * hourly_rate, 2)

    # Actuals per department from manual_entry
    cursor.execute("""
        SELECT department_code,
               COALESCE(SUM(
                   CASE 
                       WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                       ELSE ((cost / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                   END
               ), 0) AS actual_sum
        FROM manual_entry
        WHERE project_id = ?
        GROUP BY department_code
    """, (project_id,))
    actual_rows = cursor.fetchall()

    actuals_per_department = {str(dept_code): actual_sum for dept_code, actual_sum in actual_rows}

    # Working hours cost per department
    cursor.execute("""
        SELECT c.code, 
            COALESCE(SUM(w.total_cost * COALESCE(a.rate_per_hour, 1)), 0) AS working_cost
        FROM workingHours w
        LEFT JOIN admin_user a ON w.employeeID = a.username
        LEFT JOIN cost_center c ON w.departmentID = c.code
        WHERE w.projectID = ?
        GROUP BY c.code
    """, (project_id,))
    working_cost_rows = cursor.fetchall()
    working_cost_per_department = {str(dept_code): cost for dept_code, cost in working_cost_rows}

    # Add working costs into actuals
    for dept_code, working_cost in working_cost_per_department.items():
        actuals_per_department[dept_code] = actuals_per_department.get(dept_code, 0) + working_cost

    # Unique dept codes from budget and actuals
    all_dept_codes = set(budget_per_department.keys()) | set(actuals_per_department.keys())

    # Group by category with zero fill
    budget_grouped = {
        "Resources": {},
        "Material": {},
        "Sub Contract": {},
        "Site": {},
        "Others": {}
    }
    actuals_grouped = {
        "Resources": {},
        "Material": {},
        "Sub Contract": {},
        "Site": {},
        "Others": {}
    }

    total_budgets = 0
    total_actuals = 0

    valid_dept_codes = [code for code in all_dept_codes if code and code.isdigit()]
    for dept_code in sorted(valid_dept_codes, key=lambda x: int(x)):
        b_val = budget_per_department.get(dept_code, 0)
        a_val = actuals_per_department.get(dept_code, 0)
        total_budgets += b_val
        total_actuals += a_val
        cat = categorize_dept(dept_code)
        budget_grouped[cat][dept_code] = round(b_val, 2)
        actuals_grouped[cat][dept_code] = round(a_val, 2)

    # Total budget and actuals per category (sum values inside each category)
    budget_per_category = {}
    actuals_per_category = {}
    for cat in budget_grouped.keys():
        budget_per_category[cat] = round(sum(budget_grouped[cat].values()), 2)
        actuals_per_category[cat] = round(sum(actuals_grouped[cat].values()), 2)

    # Detailed per-department budget and actuals under each category for detailed charts
    budget_department_data = {}
    actual_department_data = {}

    for category in ["Resources", "Material", "Sub Contract", "Site"]:
        budget_department_data[category] = budget_grouped.get(category, {})
        actual_department_data[category] = actuals_grouped.get(category, {})

    print(".........budget_department_data.........",budget_department_data)
    print(".........actual_department_data.........",actual_department_data)

    # Debug print
    print(f"Total Budgets: {total_budgets}, Total Actuals: {total_actuals}")

    return render_template(
        'admin_templates/projects/admin_graph_view.html',
        user=user,
        department_code=department_code,
        project_details=project_details,
        user_access=user_access,
        budget_grouped=budget_grouped,
        actuals_grouped=actuals_grouped,
        total_budgets=total_budgets,
        total_actuals=total_actuals,
        actuals_per_category=actuals_per_category,
        budget_per_category=budget_per_category,
        budget_department_data=budget_department_data,
        actual_department_data=actual_department_data
    )

from flask import request, jsonify

@app.route('/allocate_hours/<int:proid>', methods=['POST'])
@login_required
def allocate_hours(proid):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_database()
    user = get_current_user()
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    cursor = db.cursor()
    current_date = datetime.date.today()

    for code, hours in data.items():
        try:
            hours_float = float(hours)
        except ValueError:
            hours_float = 0.0

        cursor.execute("SELECT 1 FROM pmtable WHERE department_code = ? AND project_id = ?", (code, proid))
        existing_record = cursor.fetchone()

        if existing_record:
            cursor.execute("""
                UPDATE pmtable
                SET added_hours = added_hours + ?, total = total + ?
                WHERE project_id = ? AND department_code = ?
            """, (hours_float, hours_float, proid, code))
        else:
            cursor.execute("""
                INSERT INTO pmtable (project_id, department_code, hours, added_hours, total)
                VALUES (?, ?, ?, ?, ?)
            """, (proid, code, hours_float, 0.0, hours_float))

        if hours_float > 0:
            db.execute("""
                INSERT INTO alloc_hrs_pmtable (project_id, username, department_code, total, date_added)
                VALUES (?, ?, ?, ?, ?)
            """, (proid, user['name'], code, hours_float, current_date))

    db.commit()
    return jsonify({"status": "success"})

from datetime import datetime

def project_alerts(project_id):
    user = get_current_user() 
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])

    messages = []

    # Check for PRs with status not 'Processed'
    # if department_code == 1000:
    cursor.execute("""SELECT PR_no, status  FROM created_pr  WHERE project_id = ? AND status != 'Processed'""", (project_id,))
    result = cursor.fetchall()
    if result:
        for pr in result:
            messages.append(f"PR Number {pr[0]} for project {project_id} is not Processed yet.")
    
    # Check for POs with DO status not 'Closed'
    cursor.execute(""" SELECT PO_no   FROM created_po   WHERE project_id = ? AND do_staus != 'Closed'""", (project_id,))
    result = cursor.fetchall()
    if result:
        for pr in result:
            messages.append(f"PO Number {pr[0]} for project {project_id} DO status is still Open.")

    # Check for payment requests with unresolved status
    # if department_code == 1000:
    cursor.execute("""SELECT pay_number, status  FROM payment_request  WHERE proj_no = ? AND status NOT IN ('Paid', 'Approved')""", (project_id,))
    result = cursor.fetchall()
    if result:
        for pr in result:
            messages.append(f"Pay Number {pr[0]} for project {project_id} status is still {pr[1]}.")

    # Check last updated working hours
    # cursor.execute(""" SELECT MAX(formatted_date)  FROM workingHours  WHERE projectID = ? """, (project_id,))
    # result = cursor.fetchone()
    # last_updated_date = result[0]

    # if last_updated_date:
    #     last_date = datetime.strptime(last_updated_date, '%Y-%m-%d')
    #     days_since_update = (datetime.now() - last_date).days

    #     if days_since_update > 4:
    #         messages.append(f"It has been {days_since_update} days since you updated working hours on this project.")
    # else:
    #     messages.append(f"No working hours have been recorded for project {project_id}.")

    return messages

@app.route('/admin_enquiry', methods=['POST', 'GET'])
@login_required
def admin_enquiry():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])

    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username( user['name'])
    cursor.execute('SELECT display_name FROM client_details')
    Cilent_suggestions = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]
    from datetime import datetime
    current_date = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT industry FROM industry')
    industry = sorted([row[0] for row in cursor.fetchall()])

    if request.method == 'POST':
        industry = request.form.get('industry')
        contact = request.form.get('contact')
        status = request.form.get('status')

        cursor = db.execute("SELECT MAX(EnquiryNumber) FROM enquiries")
        last_enquiry_number = cursor.fetchone()[0]
        eq = last_enquiry_number + 1 if last_enquiry_number is not None else 1 

        reference_number = request.form.get('reference_number')  # EnquiryNumber
        print(".....reference_number...",reference_number)
        client = request.form.get('client')
        name = request.form.get('name')
        PhoneNumber = request.form.get('phone')
        Email = request.form.get('email')
        site_or_end_user = request.form.get('site')
        received_date = request.form.get('received_date')
        submit_before_date = request.form.get('submission_date')
        date_of_submission = request.form.get('Date_Submission')
        revision_number = request.form.get('Revision_number')
        estimate_value = request.form.get('Estimated_value')
        assigned_to = request.form.get('assigned_to')

        if not estimate_value:
            estimate_value = 0
        currency = request.form.get('currency')

        # existing_enquiry = db.execute("SELECT EnquiryNumber FROM enquiries WHERE EnquiryNumber = ?", (eq,)).fetchone()
        if reference_number:
            # Update existing enquiry
            db.execute(""" UPDATE enquiries SET contact = ?, Industry = ?, Client = ?, Name = ?, SiteOrEndUser = ?, 
                           EnquiryReceived = ?, SubmitBeforeDate = ?, DateOfSubmission = ?,  RevisionNumber = ?, EstimateValue = ?, status = ?, PhoneNumber = ?, 
                           Email = ?, currency = ?, assigned_to = ? WHERE EnquiryNumber = ? """, (contact, industry, client, name, site_or_end_user, received_date, 
                           submit_before_date, date_of_submission, revision_number,  estimate_value, status, PhoneNumber, Email, currency, assigned_to, reference_number))
            flash('Enquiry updated successfully', 'success')
        else:
            # Insert new enquiry
            db.execute(""" INSERT INTO enquiries  (EnquiryNumber, contact, Industry, Client, Name, SiteOrEndUser,  EnquiryReceived, SubmitBeforeDate, 
                           DateOfSubmission, RevisionNumber,  EstimateValue, status, PhoneNumber, Email, currency, assigned_to)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                           """, (eq, contact, industry, client, name, site_or_end_user, received_date,  submit_before_date, date_of_submission, revision_number, 
                                 estimate_value, status, PhoneNumber, Email, currency, assigned_to))
            flash('Enquiry added successfully', 'success')
        db.commit()
        return redirect(url_for('admin_enquiry'))

    cursor = db.execute("""
        SELECT * FROM enquiries 
        WHERE strftime('%Y', EnquiryReceived) IN (strftime('%Y', 'now'), strftime('%Y', 'now', '-1 year')) 
        ORDER BY EnquiryNumber DESC
    """)
    enquiries = cursor.fetchall()

    query = 'SELECT username FROM admin_user WHERE department_code <= ?'
    cursor.execute(query, (1004,))  # Using parameterized query
    usernames = [row[0] for row in cursor.fetchall()]
    assigend_to_names = sorted(usernames)  # Sort the usernames alphabetically

    # Count by status
    cursor.execute("""
        SELECT status, COUNT(*) 
        FROM enquiries 
        WHERE strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
        GROUP BY status
        ORDER BY 
        CASE status
            WHEN 'Un Qualified' THEN 1
            WHEN 'Pending' THEN 2
            WHEN 'Submitted' THEN 3
            WHEN 'Lost' THEN 4
            WHEN 'Won' THEN 5
            ELSE 6
        END
    """)
    status_counts = dict(cursor.fetchall())

    # Count by industry
    cursor.execute("SELECT Industry, COUNT(*) FROM enquiries WHERE strftime('%Y', EnquiryReceived) = strftime('%Y', 'now') GROUP BY Industry")
    industry_counts = dict(cursor.fetchall())
    # Count by client
    cursor.execute("""SELECT Client, COUNT(*) FROM enquiries WHERE strftime('%Y', EnquiryReceived) = strftime('%Y', 'now') GROUP BY Client ORDER BY COUNT(*) DESC""")
    client_counts = dict(cursor.fetchall())

    from collections import defaultdict
    cursor.execute("""
        SELECT assigned_to, status, COUNT(*)
        FROM enquiries 
        WHERE strftime('%Y', EnquiryReceived) = strftime('%Y', 'now') 
        GROUP BY assigned_to, status
    """)
    raw_data = cursor.fetchall()

    # Step 1: Populate defaultdict
    assigned_to_data = defaultdict(lambda: defaultdict(int))
    for person, status, count in raw_data:
        person = person if person is not None else "Unassigned"
        status = status if status is not None else "Unknown"
        assigned_to_data[person][status] += count

    # Step 2: Sort statuses in custom order
    status_order = {'Un Qualified': 1, 'Pending': 2, 'Submitted': 3, 'Lost': 4, 'Won': 5}
    sorted_assigned_to_data = {}
    for person, statuses in assigned_to_data.items():
        sorted_statuses = dict(
            sorted(statuses.items(), key=lambda item: status_order.get(item[0], 99))
        )
        sorted_assigned_to_data[person] = sorted_statuses

    # ✅ Step 3: Use the sorted result
    assigned_to_data = sorted_assigned_to_data

    # Now `sorted_assigned_to_data` is ready for JSON serialization or rendering
    # Fetch relevant data
    # cursor.execute("""
    #     SELECT EnquiryNumber, Name, assigned_to, EnquiryReceived, SubmitBeforeDate, DateOfSubmission
    #     FROM enquiries
    #     WHERE DateOfSubmission IS NOT NULL AND SubmitBeforeDate IS NOT NULL
    # """)
    # rows = cursor.fetchall()

    # late_submissions = []
    # processing_times = []

    # for row in rows:
    #     enquiry_number, name, assigned_to, received, due, submitted = row
    #     try:
    #         received_date = datetime.strptime(received, "%Y-%m-%d")
    #         due_date = datetime.strptime(due, "%Y-%m-%d")
    #         submitted_date = datetime.strptime(submitted, "%Y-%m-%d")

    #         # Late Submission
    #         if submitted_date > due_date:
    #             late_submissions.append({
    #                 'EnquiryNumber': enquiry_number,
    #                 'Name': name,
    #                 'AssignedTo': assigned_to,
    #                 'SubmitBeforeDate': due_date.strftime('%Y-%m-%d'),
    #                 'DateOfSubmission': submitted_date.strftime('%Y-%m-%d'),
    #                 'DaysLate': (submitted_date - due_date).days
    #             })

    #         # Processing Time
    #         processing_days = (submitted_date - received_date).days
    #         processing_times.append({
    #             'EnquiryNumber': enquiry_number,
    #             'Name': name,
    #             'AssignedTo': assigned_to,
    #             'ProcessingDays': processing_days
    #         })

    #     except Exception as e:
    #         print(f"Skipping row due to error: {e}")

    # Get sum of EstimateValue grouped by status
    cursor.execute("""
        SELECT status, SUM(EstimateValue) as TotalPOValue
        FROM enquiries 
        WHERE strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
        GROUP BY status
        ORDER BY 
        CASE status
            WHEN 'Un Qualified' THEN 1
            WHEN 'Pending' THEN 2
            WHEN 'Submitted' THEN 3
            WHEN 'Lost' THEN 4
            WHEN 'Won' THEN 5
            ELSE 6
        END
    """)
    po_values = cursor.fetchall()

    po_value_counts = [{'status': row[0], 'TotalPOValue': row[1]} for row in po_values]
    today = datetime.today().date()
    # 1. Line Graph – Submissions over time
    current_year = datetime.now().year
    months_in_year = [f"{current_year}-{str(i).zfill(2)}" for i in range(1, 13)]

    # Execute your SQL query to get submission counts for each month
    cursor.execute("""
        SELECT strftime('%Y-%m', DateOfSubmission) AS SubmissionMonth, COUNT(*) as SubmissionCount
        FROM enquiries
        WHERE DateOfSubmission IS NOT NULL
        AND strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
        GROUP BY SubmissionMonth
        ORDER BY SubmissionMonth ASC
    """)
    submissions_over_time = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]

    # Create a dictionary of submission counts keyed by month (e.g., "2025-01": count)
    submissions_dict = {item['date']: item['count'] for item in submissions_over_time}

    # Now, ensure that each month from the start of the year has a submission count (defaulting to 0 if not found)
    full_submission_data = []
    for month in months_in_year:
        submission_count = submissions_dict.get(month, 0)
        full_submission_data.append({'date': month, 'count': submission_count})

    # 5. Overdue Enquiries
    cursor.execute(f"""
        SELECT COUNT(*)
        FROM enquiries
        WHERE SubmitBeforeDate < DATE('{today}')
        AND (status IN ('Submitted', 'Pending', 'Un Qualified') OR status IS NULL)
        AND strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
    """)

    overdue_enquiry_count = cursor.fetchone()[0]
    # 6. Enquiries Submitted On Time vs Late
    cursor.execute("""
        SELECT SubmitBeforeDate, DateOfSubmission
        FROM enquiries 
        WHERE SubmitBeforeDate IS NOT NULL AND DateOfSubmission IS NOT NULL AND strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
    """)
    timing_data = cursor.fetchall()
    on_time = sum(1 for row in timing_data if row[1] <= row[0])
    late = sum(1 for row in timing_data if row[1] > row[0])
    submission_timeliness = {'on_time': on_time, 'late': late}

    # 7. Upcoming Submissions Due
    cursor.execute(f"""
        SELECT EnquiryNumber, Client, Name, SubmitBeforeDate, status
        FROM enquiries
        WHERE SubmitBeforeDate >= DATE('{today}')
        AND (status != 'Submitted' OR status IS NULL)
        ORDER BY SubmitBeforeDate ASC
        LIMIT 4
    """)
    upcoming_submissions = [dict(zip(['EnquiryNumber', 'Client', 'Name', 'SubmitBeforeDate', 'status'], row)) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT 
            CASE 
                WHEN Industry IS NULL OR TRIM(Industry) = '' THEN 'Unknown'
                ELSE Industry
            END AS Industry,
            SUM(EstimateValue) AS TotalPoValue
        FROM enquiries
        WHERE status = 'Won' AND strftime('%Y', EnquiryReceived) = strftime('%Y', 'now')
        GROUP BY Industry
        ORDER BY TotalPoValue DESC
    """)

    industry_po_value = [dict(zip(['Industry', 'TotalPoValue'], row)) for row in cursor.fetchall()]
    user_access = get_employee_access_control(user['name'])
    return render_template("admin_templates/projects/admin_enquiry.html",current_date=current_date,enq_ids=enq_ids,
                           is_pm=is_pm,user = user,department_code=department_code, enquiries=enquiries,industry=industry,
                           assigend_to_names=assigend_to_names,user_access=user_access, Cilent_suggestions=Cilent_suggestions,
                           status_counts=status_counts, po_value_counts=po_value_counts,
                           industry_counts=industry_counts, industry_po_value=industry_po_value,
                           client_counts=client_counts,
                           assigned_to_data=assigned_to_data,
                           full_submission_data=full_submission_data,
                           overdue_enquiries=overdue_enquiry_count,
                           submission_timeliness=submission_timeliness,
                           upcoming_submissions=upcoming_submissions)

@app.route('/get_enquiry_details_to_edit/<int:enquiry_number>', methods=['GET'])
def get_enquiry_details_to_edit(enquiry_number):
    db = get_database()
    cursor = db.cursor()
    enquiry = cursor.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (enquiry_number,)).fetchone()

    if enquiry:
        return jsonify(dict(enquiry))
    else:
        return jsonify({"error": "Enquiry not found"}), 404

@app.route('/updateproject', methods=["POST", "GET"])
@login_required
def updateproject():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    user = get_current_user()

    if request.method == 'POST':
        # print("...........................yes")
        projectId = request.form['projectid']
        client = request.form['client']
        projectName = request.form['projectname']
        startTime = request.form['start_time']
        endTime = request.form['end_time']
        status = request.form['status']
        po_number = request.form['po_number']
        po_value = request.form['po_value']
        pm = request.form['projectmanager']
        billing_address =request.form['billing_address1']
        billing_address2 =request.form['billing_address2']
        billing_address3 =request.form['billing_address3']
        delivery_address = request.form['delivery_address1']
        delivery_address2 = request.form['delivery_address2']
        delivery_address3 = request.form['delivery_address3']
        type = request.form['type']
        selected_members = request.form.get('selected_members', '')

        db = get_database()
        cursor = db.cursor()
        
        cursor.execute('SELECT id FROM projects WHERE id = ?', [projectId])
        existing_project = cursor.fetchone()
        
        if existing_project:

            db.execute(""" UPDATE projects SET  client = ?, project_name = ?, start_time = ?, end_time = ?, status = ?, po_number = ?, po_value = ?, pm = ?, 
               delivery_address = ?, billing_address = ?, type = ?, project_members = ?,
                billing_address2 = ?,billing_address3 = ?,delivery_address2 = ?,delivery_address3 = ? WHERE id = ? """, 
               (client, projectName, startTime, endTime, status, po_number, po_value, pm,  delivery_address, billing_address, type, selected_members,
                billing_address2,billing_address3,delivery_address2,delivery_address3,projectId))

        db.commit()

        return redirect(url_for('projects'))

@app.route('/deletepro/<int:proid>', methods=["GET", "POST"])
@login_required
def deletepro(proid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM workingHours WHERE projectID = ?', [proid])
        db.execute('DELETE FROM projects WHERE id = ?', [proid])
        db.execute('DELETE FROM pmtable WHERE project_id = ?', [proid])
        # db.execute('DELETE FROM temp_workingHours WHERE project_id = ?', [proid])
        # db.execute('DELETE FROM workingHours WHERE project_id = ?', [proid])
        db.commit()
        return redirect(url_for('index'))
    return render_template('index.html', user=user)

from datetime import datetime
@app.route('/get_project_details', methods=['POST'])
@login_required
def get_project_details1():
    project_id = request.form.get('project_id')
    db = get_database()
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()

    if project_details:
        keys = ('id','client', 'project_name', 'start_time', 'end_time', 'pm_status', 'pe_status', 'status', 'po_number', 'pm', 'pe','po_value')
        result_dict = {key: value if value is not None else 'N/A' for key, value in zip(keys, project_details)}
        return jsonify(result_dict)
    else:
        return jsonify({'error': 'Project not found'}), 404

@app.route('/get_gst', methods=['POST'])
def get_gst():
    from datetime import datetime
    invoice_date = request.json.get('invoice_date')
    year = datetime.strptime(invoice_date, '%Y-%m-%d').year

    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT GST FROM GST WHERE strftime('%Y', Date) = ?", (str(year),))
    gst = cursor.fetchone()
    if not gst:
        cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
        gst = cursor.fetchone()
    if gst:
        return jsonify({'gst_value': gst[0]})
    else:
        return jsonify({'gst_value': None}), 404

@app.route("/check_invoice_number_supplier_name", methods=["POST"])
def check_invoice_number_supplier_name():
    data = request.get_json()
    invoice_no = data.get("invoice_no")
    supplier_name = data.get("supplier_name")

    db = get_database()
    cursor = db.cursor()

    cursor.execute("""
        SELECT 1 FROM payment_request 
        WHERE invoice_no = ? AND supplier_name = ?
    """, (invoice_no, supplier_name))
    exists = cursor.fetchone() is not None
    return jsonify({"exists": exists})

@app.route('/prj_pay_req', methods=['GET', 'POST'])
@login_required
def prj_pay_req():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    project_id = request.args.get('project_id', type=int)
    from datetime import datetime

    if request.method == 'POST':
        pay_req_no1 = request.form.get('pay_req_no')
        cursor.execute("SELECT MAX(id) FROM payment_request")
        result = cursor.fetchone()
        max_pr = result[0] if result[0] else 0
        sequential_number = max_pr + 1
        current_date = datetime.now()
        year = current_date.strftime("%y")
        pay_req_no = f"ER-{year}-{sequential_number:04}"
        project_id = request.form.get('project_id')
        pay_date = request.form.get('pay_date')
        po_number = request.form.get('po_number')
        invoice_no = request.form.get('invoice_no')
        Invoice_date = request.form.get('Invoice_date')
        total_amount = request.form.get('total_amount')
        gst_stat = request.form.get('gst_stat')
        gst_value = request.form.get('gst_value')
        gst_percent = float(request.form.get('gst_percent', 0))
        overall_total_amount = request.form.get('overall_total_amount')
        project_name = request.form.get('project_name')
        supplier_name = request.form.get('supplier_name')
        attachment = request.files.get('attachment')  # Get the attachment from the form

        if attachment:
            # Save the file to a directory
            upload_dir = 'docment_data/payment_request_invoices'
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)  # Ensure the directory exists

            # Rename the file to pay_req_no with the same file extension
            cursor.execute("SELECT id FROM payment_request ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            id = result[0] if result else 0

            # Get the file name and extension
            file_name, file_extension = os.path.splitext(attachment.filename)  # Separate the file name and extension
            new_filename = f"{id}-{file_name}{file_extension}"  # Combine id, original file name, and file extension
            filename = os.path.join(upload_dir, new_filename)
            attachment.save(filename)
            print(f"File uploaded successfully: {filename}")
        
        else:
            new_filename = None  # No file uploaded
            print("No file uploaded.")

        items = request.form.get('items')  
        Terms = request.form.get('Terms')  
        time_period = request.form.get('time_period')  
        comments = request.form.get('comments')  
        downpayment = request.form.get('downpayment') 
 
        import json
        items = json.loads(items)

        query = """ SELECT PO_number, SUM(CAST(total AS REAL)) AS total_value FROM po_items WHERE PO_number = ? GROUP BY PO_number"""
        result = db.execute(query, (po_number,)).fetchone()
        po_total_value = result['total_value'] if result else 0


        # Query to get Currency and Exchange_rate for the given po_number
        query = "SELECT Currency, Exchange_rate FROM created_po WHERE PO_no = ?"
        result = db.execute(query, (po_number,)).fetchone()

        if result:
            Currency = result['Currency']
            Exchange_rate = result['Exchange_rate']
        else:
            Currency = None
            Exchange_rate = None

        if downpayment and float(downpayment) > 0:
            downpayment_percentage = float(downpayment)
            db.execute("UPDATE created_po SET downpayment = ? WHERE PO_no = ?", (downpayment, po_number))
            db.commit()
            downpayment = po_total_value * downpayment_percentage / 100
            # Insert loop with recalculated amounts
            query = """SELECT id, Part_No, item, quantity, Unit_Price, total FROM po_items WHERE PO_number = ?"""
            po_items = db.execute(query, (po_number,)).fetchall()
            downpayment_amount_total = 0
            for row in po_items:
                item_base_amount = float(row['total'])
                downpayment_amount = round(item_base_amount * downpayment_percentage / 100, 2)  # Simple % of item value

                cursor.execute("""INSERT INTO payment_req_items 
                    (item_id, pay_number, invoice_no, pay_date, proj_no, po_NO, status, req_by,
                    Part_No, item, req_quantity, Unit_Price, req_total)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (row['id'], pay_req_no, invoice_no, pay_date, project_id, po_number, 'Pending',
                    user['name'], row['Part_No'], row['item'], 0, 0, downpayment_amount)
                )
                downpayment_amount_total += downpayment_amount


            if gst_stat == "True":
                downpayment_gst_value = round(downpayment_amount_total * gst_percent / 100, 2 )
            else:
                downpayment_gst_value = 0

            cursor.execute(""" INSERT INTO payment_request (pay_number, invoice_no, Invoice_date, pay_date, proj_no, po_number,
                            status, created_by, gst_stat, gst_value, amount, overall_total_amount , invoice_file_name,project_name, supplier_name,
                            Terms,time_period,balence,comments, downpayment , Currency ,Exchange_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?,?) 
                """, (pay_req_no, invoice_no,Invoice_date, pay_date, project_id, po_number, 'Pending', user['name'], gst_stat, downpayment_gst_value,downpayment_amount_total,
                        downpayment_amount_total + downpayment_gst_value,new_filename,project_name, supplier_name,Terms,time_period,downpayment_amount_total + downpayment_gst_value,
                          comments ,downpayment, Currency, Exchange_rate))

            db.commit()
        
        else:

            for item in items:
                item_id = item.get('id')
                part_no = item.get('part_no')
                item_name = item.get('item_name')
                req_quantity = float(item.get('request_qty', 0))
                unit_price = float(item.get('unit_price', 0))
                req_total = float(item.get('amount', 0))

                cursor.execute("""INSERT INTO payment_req_items 
                    (item_id, pay_number, invoice_no, pay_date, proj_no, po_NO, status, req_by,
                     Part_No, item, req_quantity, Unit_Price, req_total)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item_id, pay_req_no, invoice_no, pay_date, project_id, po_number, 'Pending',
                     user['name'], part_no, item_name, req_quantity, unit_price, req_total))



            cursor.execute(""" INSERT INTO payment_request (pay_number, invoice_no, Invoice_date, pay_date, proj_no, po_number,
                        status, created_by, gst_stat, gst_value, amount, overall_total_amount , invoice_file_name,project_name, supplier_name,
                           Terms,time_period,balence,comments,Currency ,Exchange_rate) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
            """, (pay_req_no, invoice_no,Invoice_date, pay_date, project_id, po_number, 'Pending', user['name'], gst_stat, gst_value,total_amount,
                    overall_total_amount,new_filename,project_name, supplier_name,Terms,time_period,overall_total_amount, comments, Currency, Exchange_rate))


        db.commit()
        total_amount = float(total_amount)  # Convert to float if it's not already
        total_amount = locale.format_string('%.2f', total_amount, grouping=True)

        user_cur = db.execute('SELECT pm, project_members FROM projects WHERE id = ?', (project_id,))
        mail_to_row = user_cur.fetchone()

        if not mail_to_row:
            print("No project found for the given ID.")
            return []  # Return an empty list if no project is found
        
        pm, project_members = mail_to_row
        mail_to_list = []
        
        if pm == user['name']:
            # Fetch names from `admin_user` table where `department_code` is 1000
            team_cur = db.execute('SELECT name FROM admin_user WHERE department_code = 1000')
            mail_to_list = [row[0] for row in team_cur.fetchall()]
        
        else:
            # Include `pm` and fetch names where `department_code` is 1000
            mail_to_list.append(pm)
            team_cur = db.execute('SELECT name FROM admin_user WHERE department_code = 1000')
            mail_to_list.extend([row[0] for row in team_cur.fetchall()])

        roles_cur = db.execute('''SELECT employee FROM roles WHERE primary_role_code = 11 OR sencondary_role_code = 11''')
        employees_with_role_11 = [row[0] for row in roles_cur.fetchall()]

        if employees_with_role_11:
            placeholders = ', '.join(['?'] * len(employees_with_role_11))
            query = f'SELECT name FROM admin_user WHERE username IN ({placeholders})'
            names_cur = db.execute(query, employees_with_role_11)
            mail_to_list.extend([row[0] for row in names_cur.fetchall()])

        mail_to_list = list(set(mail_to_list))
        import re
        print("...........mail_to_list.............",mail_to_list)
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        valid_emails = []

        for email in mail_to_list:
            if re.match(email_regex, email):
                valid_emails.append(email)  # Add to valid email list

        print("........valid_emails............", valid_emails)

        try:
            print("........valid_emails............", valid_emails)

            # Payment_Request_Notification(valid_emails, user['name'], project_id, po_number, total_amount, pay_req_no)
        except Exception as e:
            print(f"[Notification Error] Failed to send emails: {e}")

        return redirect(url_for('prj_pay_req', project_id=project_id))


    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])  
    user_access = get_employee_access_control(user['name'])

    # Fetch project details
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()

    cursor = db.execute('SELECT * FROM payment_request WHERE proj_no = ? ORDER BY id DESC',(project_id,))
    payment_request = cursor.fetchall()

    rows = []

    for pay in payment_request:
        id = pay[0]            # The ID column is at index 0
        pay_number = pay[1]
        invoice_no = pay[2]
        pay_date = pay[3]
        proj_no = pay[4]
        po_number = pay[5]
        status = pay[6]
        created_by = pay[7]
        approved_by = pay[8]
        paid_by = pay[9]
        amount = pay[10]
        invoice_file_name = pay[11]
        paid_date = pay[12]
        approved_date = pay[13]
        overall_total_amount = pay[14]
        Invoice_date = pay[15]
        gst_stat = pay[16]
        gst_value = pay[17]
        supplier_name = pay[18]
        project_name = pay[19]
        Terms = pay[20]
        time_period = pay[21]
        balence = pay[22] if pay[22] is not None else 0.0
        # from datetime import datetime, timedelta

        if Invoice_date:
            try:
                invoice_date = datetime.strptime(Invoice_date, "%Y-%m-%d")
                today = datetime.today().date()  # Get current date without time

                if time_period in ['Days', 'Advance']:
                    try:
                        terms_int = int(Terms)  # Ensure Terms is an integer
                        due_date = invoice_date + timedelta(days=terms_int)  # Calculate due date
                        due_days = (due_date.date() - today).days  # Days remaining from today
                    except ValueError:
                        due_date = None
                        due_days = None
                        print("Invalid value for 'Terms', expected an integer.")

                elif time_period == 'COD':  # Payment is due immediately
                    due_date = invoice_date
                    due_days = 0  # Due today

                else:
                    due_date = None
                    due_days = None

                due_date_str = due_date.strftime("%m/%d/%y") if due_date else '0/0/0'

            except ValueError:
                print("Invalid Invoice_date format, expected YYYY-MM-DD.")
                due_date = None
                due_days = None
                due_date_str = '0/0/0'
        
        else:
            due_date = None
            due_days = None
            due_date_str = '0/0/0'

        rows.append({ 'id': id,'pay_number': pay_number, 'invoice_no': invoice_no,  'pay_date': pay_date, 
                     'proj_no': proj_no,'po_number': po_number, 'status': status, 'created_by': created_by, 'amount' : amount,
                    'approved_by': approved_by, 'paid_by': paid_by, 'invoice_file_name' : invoice_file_name,
                    'paid_date' : paid_date, 'approved_date' : approved_date, 'overall_total_amount' :overall_total_amount,
                     'Invoice_date' : Invoice_date,  'gst_stat': gst_stat, 'gst_value' : gst_value, 'supplier_name':supplier_name,
                       'project_name':project_name,'Terms': Terms,'time_period':time_period ,'due_date':due_date_str,
                        'due_days': due_days,'balence': balence,  })

    grouped_df = pd.DataFrame(rows)

    if 'status' in grouped_df.columns:
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3})
        grouped_df = grouped_df.sort_values('status_order')
    
    else:
        # print("The 'status' column is missing from rows.")
        grouped_df['status'] = 'Unknown'  # Add a default status or handle differently
        grouped_df['status_order'] = grouped_df['status'].map({'Pending': 1, 'Partial': 2, 'Paid': 3}).fillna(0)
        grouped_df = grouped_df.sort_values('status_order')
    grouped_df = grouped_df.to_dict('records')

    # print(".......grouped_df............",grouped_df)
    return render_template('admin_templates/projects/prj_pay_req.html',
                        is_pm=is_pm, department_code=department_code,
                        user_access=user_access, user=user,grouped_df=grouped_df,
                        project_id=project_id, project_details=project_details)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def Payment_Request_Notification(valid_emails, requested_by, project_id, po_number, total_amount, pay_req_no):
    try:
        # Establish connection with SMTP server
        s = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10)
        s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

        # Email subject and body
        subject = f"{pay_req_no}"
        body = (
            f"Dear Sir/Madam,\n"
            f"This is to inform you that a new Payment Request by {requested_by}\n\n"
            f"Request Details:\n"
            f"Payment Request ID : {pay_req_no}\n"
            f"Project ID : {project_id}\n"
            f"PO Number : {po_number}\n"
            f"Amount : $ {total_amount}\n\n"
            "We kindly request your approval for the Payment at your earliest convenience.\n"
            "Thank you for your attention to this matter.\n\n"
            "Best regards,\n"
            "Centroid Engineering Solutions"
        )

        # Send email to each recipient
        for mail_to in valid_emails:
            message = MIMEMultipart()
            message['From'] = "cestimesheet67@gmail.com"
            message['To'] = mail_to
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            try:
                s.sendmail("cestimesheet67@gmail.com", mail_to, message.as_string())
                print(f"PR approval request email sent to {mail_to} successfully.")
            except Exception as e:
                print(f"Failed to send email to {mail_to}: {e}")

        s.quit()

    except Exception as e:
        print(f"[Email Error] Could not send payment request emails: {e}")

import os
from flask import Flask, send_from_directory

@app.route('/docment_data/payment_request_invoices/<path:filename>')
def view_pay_req_invoice_file(filename):
    directory = os.path.abspath(r'docment_data\payment_request_invoices')
    # List of common file extensions
    extensions = [
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Images
    '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',  # Documents and spreadsheets
    '.html', '.htm', '.xml', '.json',  # Web and data files
    '.zip', '.tar', '.gz', '.rar',  # Archive files
    '.mp3', '.wav', '.ogg',  # Audio files
    '.mp4', '.avi', '.mkv', '.mov', '.webm',  # Video files
    '.svg', '.eps', '.ai',  # Vector images
    '.psd', '.indd',  # Adobe files (Photoshop, InDesign)
    '.epub', '.mobi', '.azw3',  # Ebook formats
    '.pptx', '.key',  # Presentation files
    '.xlsx', '.ods',  # Spreadsheet formats
    '.json', '.yaml',  # Configuration and data files
    '.md', '.rst',  # Markup files
    '.exe', '.msi', '.dmg',  # Executables and install files
    ]

    
    # Try each extension until we find the correct one
    for ext in extensions:
        file_path = os.path.join(directory, filename )
        print(f"Checking file path: {file_path}")
        
        if os.path.exists(file_path):
            return send_from_directory(directory, filename, as_attachment=False)
    
    return "File not found", 404

@app.route('/delete_payment_req', methods=['POST'])
@login_required
def delete_payment_req():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "Unauthorized access"}), 401
    data = request.get_json()
    id = data.get('id')
    if not id:
        return jsonify({"success": False, "message": "DO number is required"}), 400
    db = get_database()
    cursor = db.cursor()

    try:
        # Delete from `do_items` table
        cursor.execute("UPDATE payment_request SET status = 'Canceled' WHERE id =  ?", (id,))

        db.commit()  # Commit the changes
        return jsonify({"success": True, "message": f"Request {id} Cancled successfully"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_po_numbers', methods=['POST'])
def get_po_numbers():
    project_id = request.json.get('project_id')
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT PO_no FROM created_po WHERE project_id = ? AND (payment_status IS NULL OR payment_status != 'Closed')", (project_id,))
    po_numbers_rows = cursor.fetchall()  # Fetch all rows
    po_numbers = [row['PO_no'] for row in po_numbers_rows] if po_numbers_rows else []

    if not po_numbers:  # Check if the list is empty
        return jsonify({'error': 'No PO numbers found for the project'}), 404

    # Fetch project details
    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project = cursor.fetchone()

    if project is None:
        return jsonify({'error': 'Project not found'}), 404

    if project['status'] == 'Closed':
        return jsonify({'error': 'Project is closed. Cannot request payment'}), 400

    # Generate the DO number
    cursor.execute("SELECT MAX(id) FROM payment_request")
    result = cursor.fetchone()
    max_pr = result[0] if result[0] else 0
    sequential_number = max_pr + 1
    from datetime import datetime

    current_date = datetime.now()
    year = current_date.strftime("%y")
    pay_req_no = f"Auto Generated "
    formatted_date = current_date.strftime("%Y-%m-%d")  # "2024-12-30"

    # Prepare project details for response
    project_details = {
        'project_id': project_id,
        'client': project['client'],
        'po_numbers': po_numbers,
        'pay_date': formatted_date,
        'pay_req_no' : pay_req_no
    }
    # print(".project_details.........",project_details)

    return jsonify(project_details)

@app.route('/get_po_items', methods=['POST'])
def get_po_items():
    data = request.json
    po_number = data.get('po_number')
    project_id = data.get('project_id')

    if not po_number or not project_id:
        return jsonify({"error": "PO Number and Project ID are required"}), 400

    try:
        db = get_database()
        cursor = db.cursor()

        # Query PO details from created_po
        cursor.execute(""" 
            SELECT PO_no, Quote_Ref, Expenses, Payment_Terms, Currency, status, total, Attn ,Supplier_Name, downpayment,Discount 
                       FROM created_po  WHERE PO_no = ? AND project_id = ? """, (po_number, project_id))

        po_details = cursor.fetchone()
        if not po_details:
            return jsonify({"error": "PO details not found for the provided PO Number and Project ID"}), 404

        po_number = po_details[0]
        query = """ SELECT PO_number, SUM(CAST(total AS REAL)) AS total_value FROM po_items WHERE PO_number = ? GROUP BY PO_number"""
        result = db.execute(query, (po_number,)).fetchone()
        po_total_value = result['total_value'] if result else 0
        query = "SELECT downpayment FROM created_po WHERE PO_no = ?"
        result = db.execute(query, (po_number,)).fetchone()

        if result:
            downpayment_value = result['downpayment']
        else:
            print("PO number not found.")
            downpayment_value = None

        po_data = {
            "PO_no": po_details[0],
            "Quote_Ref": po_details[1],
            "Expenses": po_details[2],
            "Payment_Terms": po_details[3],
            "Currency": po_details[4],
            "status": po_details[5],
            "total": po_total_value,
            "Attn": po_details[7],
            "Supplier_Name" : po_details[8],
            "Discount" : po_details[10],
            "downpayment" : downpayment_value,
        }

        cursor.execute("SELECT GST FROM po_items WHERE PO_number = ?", (po_number,))
        gst_row = cursor.fetchone()

        if gst_row is not None:
            gst_value = gst_row[0]
            # Determine gst_status
            gst_status = "True" if gst_value > 2.0 else "False"

        # Query PO items
        cursor.execute(""" SELECT id, Part_No, item, uom, quantity, Unit_Price, total  FROM po_items WHERE PO_number = ? AND project_id = ?  """, (po_number, project_id))

        po_items = cursor.fetchall()
        # print("....po_items..........",po_items)

        items = []
        for row in po_items:
            item_id = row[0]
            part_no = row[1]
            item_name = row[2]
            uom = row[3]
            quantity = float(row[4])  # Convert to float
            unit_price = float(row[5])  # Convert to float
            total = float(row[6])  # Convert to float


            # Query payment request details for the current item
            cursor.execute("""
                SELECT 
                    ROUND(COALESCE(SUM(req_quantity), 0), 2) AS req_qty,
                    ROUND(COALESCE(SUM(req_total), 0), 2) AS req_total
                FROM payment_req_items
                WHERE item_id = ? AND po_no = ? AND proj_no = ?
            """, (item_id, po_number, project_id))
            row = cursor.fetchone()

            req_qty = row[0]  # Rounded to 2 decimals
            req_total = row[1]  # Rounded to 2 decimals
            # print(".....req_qty......req_total....",req_qty,req_total)
            # print(".......req_qty.....",type(req_qty))
            # print(".......req_total.....",type(req_total))

            # Calculate balance quantities and amounts
            balance_qty = quantity - req_qty
            balance_amount = total - req_total

            # Round the values to 2 decimal places
            balance_qty = round(balance_qty, 2)
            balance_amount = round(balance_amount, 2)

            # Print the rounded values
            # print(".....balance_qty......balance_amount....", balance_qty, balance_amount)


            items.append({
                "id": item_id,
                "Part_No": part_no,
                "item": item_name,
                "uom": uom,
                "quantity": quantity,
                "Unit_Price": unit_price,
                "total": total,
                "req_qty": req_qty,
                "req_total": req_total,
                "balance_qty": balance_qty,
                "balance_amount": balance_amount
            })
            # print(".........items............",items)

        # Combine PO details and items in the response
        return jsonify({"po_details": po_data, "item_list": items, "gst_status" : gst_status})

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Failed to fetch PO details or items"}), 500
    finally:
        db.close()

@app.route('/project_do', methods=['GET', 'POST'])
@login_required
def project_do():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    project_id = request.args.get('project_id', type=int)

    # Handle form submission
    if request.method == 'POST':

        DO_number = request.form.get ('DO_Print')

        if DO_number:

            cursor.execute('SELECT * FROM created_do WHERE do_number = ?', (DO_number,))
            do_details = cursor.fetchone()

            cursor.execute(''' SELECT item_name, index_number, qty, Unit FROM do_items WHERE do_number = ? ''', (DO_number,))
            do_items = cursor.fetchall()
            # Ensure that we have po_items before proceeding
            if do_items:
                print("........entered n side the if condition................")
                # Create data for PDF
                data_dict = []
                total_sum = 0
                for index, item in enumerate(do_items):  # Use enumerate to get index and item
                    item_dict = {
                        'index': str(item[1]),  
                        'item': str(item[0]),     
                        'quantity': str(item[2]),  
                        'Unit': str(item[3]), 
                    }
                    data_dict.append(item_dict)
                pdf_file = new_do_pdf(data_dict, do_details)
                if pdf_file:
                    db.commit()  # Save changes if any
                    return send_file(pdf_file, download_name=f"{do_details['do_number']}.pdf", as_attachment=True, mimetype='application/pdf')
            else:
                print("..............................................No items found for the selected DO number.")
                return redirect(url_for('project_do'))

    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])  
    user_access = get_employee_access_control(user['name'])

    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor.execute("SELECT * FROM do_items WHERE proj_no = ?", (project_id,))
    items = cursor.fetchall()
    cursor = db.execute('SELECT * FROM created_do WHERE proj_no = ? ORDER BY id DESC',(project_id,))
    created_do = cursor.fetchall()



    return render_template('admin_templates/projects/project_do.html',
                        is_pm=is_pm, department_code=department_code,created_do=created_do,
                        user_access=user_access, user=user,
                        project_id=project_id, project_details=project_details, items=items)

@app.route('/create_do_with_items', methods=['POST'])
def create_do_with_items():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_database()
    cursor = db.cursor()
    user = get_current_user()

    project_id = request.form.get('project_id')
    po_number = request.form.get('po_number')
    Project_Ref = request.form.get('Project_Ref')
    Attn = request.form.get('Attn')
    from datetime import datetime
    cursor.execute("SELECT MAX(id) FROM created_do")
    result = cursor.fetchone()
    max_pr = result[0] if result[0] else 0
    sequential_number = max_pr + 1
    current_date = datetime.now()
    year = current_date.strftime("%y")
    do_number = f"D-{year}-{sequential_number:04}"
    formatted_date = current_date.strftime("%d-%m-%y")
    do_date = request.form.get('do_date')
    client = request.form.get('client_add')
    client_add_l1 = request.form.get('client_Address_Line1')
    client_add_l2 = request.form.get('client_Address_Line2')
    client_add_l3 = request.form.get('client_Address_Line3')
    delivery = request.form.get('Delivery_add')
    delivery_add_l1 = request.form.get('delivary_Address_Line1')
    delivery_add_l2 = request.form.get('delivary_Address_Line2')
    delivery_add_l3 = request.form.get('delivary_Address_Line3')
    Remarks = request.form.get('Remarks')
    Warranty = request.form.get('Warranty')
    status = 'Open'  # You can adjust the status as needed
    created_by = user['name']
    
    cursor.execute("""INSERT INTO created_do (do_number, do_date, proj_no, client, client_add_l1, client_add_l2, client_add_l3, delivery, 
                        delivery_add_l1, delivery_add_l2, delivery_add_l3, po_number, status, created_by, Project_Ref, Attn, Remarks,Warranty) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (do_number, do_date, project_id, client, client_add_l1, client_add_l2, client_add_l3, delivery, delivery_add_l1,
                    delivery_add_l2, delivery_add_l3, po_number, status, created_by, Project_Ref, Attn, Remarks, Warranty))

    index_number = request.form.getlist('index_number[]') or []
    description_headers = request.form.getlist('description_header[]') or []
    description_subheaders = request.form.getlist('description_subheader[]') or []
    description_bodys = request.form.getlist('description_body[]') or []
    quantities = request.form.getlist('quantity[]') or []
    unit_prices = request.form.getlist('unit_price[]') or []

    index_number = [str(i).strip() for i in index_number]
    description_headers = [str(h).strip() for h in description_headers]
    description_subheaders = [str(sh).strip() for sh in description_subheaders]
    description_bodys = [str(b).strip() for b in description_bodys]
    quantities = [q if q not in [None, ""] else 0 for q in quantities]
    unit_prices = [p if p not in [None, ""] else 0 for p in unit_prices]

    for i in range(len(description_bodys)):
        lines = []
        header = description_headers[i].strip() if i < len(description_headers) and description_headers[i] else ""
        subheader = description_subheaders[i].strip() if i < len(description_subheaders) and description_subheaders[i] else ""
        body = description_bodys[i].strip() if i < len(description_bodys) and description_bodys[i] else ""

        if header:
            lines.append(f"Header - {header}")
        if subheader:
            lines.append(f"Subheader - {subheader}")
        if body:
            lines.append(f"Body - {body}")

        description = "\n".join(lines) if lines else " "

        qty_raw = quantities[i] if i < len(quantities) else None
        unit_raw = unit_prices[i] if i < len(unit_prices) else None
        index_raw = index_number[i] if i < len(index_number) else None

        try:
            quantity = float(qty_raw)
        except (TypeError, ValueError):
            quantity = None  
        unit_price = None if unit_raw in [None, "", "0", 0] else unit_raw
        index_num = None if index_raw in [None, "", "0", 0] else str(index_raw).strip()

        cursor.execute("""INSERT INTO do_items (index_number, do_number, proj_no, status, item_name, qty, Unit) 
            VALUES (?, ?, ?, ?, ?, ?, ?) """, (index_num, do_number, project_id, 'Open', description, quantity, unit_price))

    db.commit()  

    return redirect(url_for('project_do', project_id=project_id))

import unicodedata
import re

def normalize_do_text(text):
    if isinstance(text, str):
        # Replace ligatures
        text = text.replace("\ufb01", "fi").replace("\ufb02", "fl")
        text = text.replace("\ufb03", "ffi").replace("\ufb04", "ffl")
        
        # Normalize Unicode characters
        text = unicodedata.normalize('NFC', text)

        # Replace common quotation marks and dashes
        text = text.replace("”", "\"").replace("“", "\"")
        text = text.replace("‘", "'").replace("’", "'")
        text = text.replace("\u2013", "-").replace("\u2014", "-")

        # Remove invisible/zero-width characters
        text = re.sub(r'[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]', '', text)

        # Remove characters not encodable in latin-1
        text = text.encode('latin1', errors='ignore').decode('latin1')
        
    return text

def new_do_pdf(data_dict, do_details):
    if isinstance(do_details, sqlite3.Row):
        do_details = dict(do_details)
    
    if isinstance(data_dict, sqlite3.Row):
        data_dict = dict(data_dict)

    if isinstance(data_dict, list):
        data_dict = [
            {k: normalize_do_text(v) if k not in ['Part_No', 'item'] else normalize_do_text(v) for k, v in item.items()} for item in data_dict]
    else:
        data_dict = {k: normalize_do_text(v) if k not in ['Part_No', 'item'] else normalize_do_text(v) for k, v in data_dict.items()}
    
    do_details = {k: normalize_do_text(v) for k, v in do_details.items()}
    pdf_output = BytesIO()
    pdf = DO_PDF(data_dict, do_details)  
    pdf.add_page()  
    pdf.body()
    pdf_output.write(pdf.output(dest='S').encode('latin1')) 
    pdf_output.seek(0)  
    return pdf_output 

class DO_PDF(FPDF):

    def __init__(self, data_dict, do_details, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.do_details = do_details
        self.data_dict = data_dict
        self.max_y = 0
        self.page_height = 292  # Adjust this value based on your page size
        self.alias_nb_pages() # <--- Make sure this line is present

    def header(self):
        self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
        self.rect(2, 2 , 205, 292)
        image_path = os.path.join('static', 'CENTROID Logo.jpg')  

        # Try to add the CENTROID Logo image
        try:
            self.image(image_path, 145, 5, 50)  # Only width is specified, height is auto-scaled.
        except Exception as e:
            print(f"Error loading image {image_path}: {e}")

        self.set_font('helvetica', '', 12)
        # Company details aligned to the leftmost side
        self.set_xy(2, 5)  # Start text at the leftmost side of the page

        # Company details
        self.cell(0, 6, 'Centroid Engineering Solutions Pte Ltd', ln=True)
        self.set_x(2)  # Reset x-coordinate after each line break
        self.cell(0, 6, 'Co Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'GST Regn No: 201308058R', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, '11, Woodlands Close, #07-10', ln=True)
        self.set_x(2)  # Reset x-coordinate
        self.cell(0, 6, 'Singapore - 737853', ln=True)

        # Move the title to be in between the logo and the details
        self.set_xy(25, 28)  # Adjust position of the title (center between details and logo)
        self.set_font('helvetica', 'B', 20)  # Title in bold
        self.cell(0, 10, 'DELIVERY ORDER', ln=True, align='C')  # Title in the center

        self.line(2, 39, 207, 39)  # Line from x=10 to x=200 at y=40

        # Client Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 40)
        self.cell(0, 6, 'Client', ln=False)
        self.set_xy(19, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(21, 40)
        self.cell(0, 6, self.do_details['client'], ln=True)

        # Client Address
        self.set_x(21)
        self.cell(0, 6, self.do_details['client_add_l1'], ln=True)
        self.set_x(21)
        self.cell(0, 6, self.do_details['client_add_l2'], ln=True)
        self.set_x(21)
        self.cell(0, 6, self.do_details['client_add_l3'], ln=True)
        self.set_x(21)

        # Attn Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 64)
        self.cell(0, 6, 'Attn', ln=False)
        self.set_xy(19, 64)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.do_details['Attn'], ln=True)

        # PO Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(145, 40)
        self.cell(0, 6, 'DO No', ln=False)
        self.set_xy(145, 46)
        self.cell(0, 6, 'DO Date', ln=False)
        self.set_xy(145, 52)
        self.cell(0, 6, 'PO No', ln=False)
        self.set_xy(145, 58)
        self.cell(0, 6, 'Project Ref', ln=False)
        self.set_xy(145, 64)
        self.cell(0, 6, 'Page', ln=False)
        # Add the page number here (e.g., 1 of N)
        self.set_font("helvetica", "", 10) # Set back to regular font for the value
        # Adjust X position to align with other values
        self.set_x(167) # You'll need to fine-tune this X position based on your layout
        self.cell(0, 6, f"{self.page_no()} of {{nb}}", 0, 1, 'L') # Using {nb} for total pages

        # PO Values
        self.set_font("helvetica", "B", 10)
        self.set_xy(165, 40)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(167, 40)
        self.cell(0, 6, self.do_details['do_number'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(165, 46)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(167, 46)
        self.cell(0, 6, self.do_details['do_date'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(165, 52)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(167, 52)
        self.cell(0, 6, self.do_details['po_number'][:20] , ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(165, 58)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(167, 58)
        self.cell(0, 6, self.do_details['Project_Ref'], ln=True)

        self.set_font("helvetica", "B", 10)
        self.set_xy(165, 64)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_xy(167, 64)
        # self.cell(0, 6,  '1', ln=True)
        self.line(2, 70, 207, 70)  # Line from x=10 to x=200 at y=40

        # Delivery Details
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 70)
        self.cell(0, 6, 'Delivery', ln=False)
        self.set_xy(19, 70)
        self.cell(0, 6, ':', ln=False)
        self.set_font("helvetica", "", 10)
        self.set_x(21)
        self.cell(0, 6, self.do_details['delivery'], ln=True)

        # Delivery Address
        self.set_xy(21, 76)
        self.cell(0, 6, self.do_details['delivery_add_l1'], ln=True)
        self.set_xy(21, 82)
        self.cell(0, 6, self.do_details['delivery_add_l2'], ln=True)
        self.set_xy(21, 88)
        self.cell(0, 6, self.do_details['delivery_add_l3'], ln=True)
        self.line(2, 94, 207, 94)  # Line from x=10 to x=200 at y=40
        # Column widths
        item_width = 10
        description_width = 85
        qty_width = 20
        unit_price_width = 25
        # Item table heading
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 95)
        self.cell(item_width, 6, 'Item', ln=False)
        # self.line(5 + item_width, 94, 5 + item_width, 265)  # Vertical line

        self.set_xy(75, 95)
        self.cell(description_width, 6, 'Description', ln=False)
        # self.line(49 + description_width, 94, 49 + description_width, 265)  # Vertical line

        self.set_xy( 168, 95)
        self.cell(qty_width, 6, 'Qty', ln=False)
        # self.line(160 + unit_price_width, 94, 160 + unit_price_width, 265)  # Vertical line

        self.set_xy(194, 95)
        self.cell( unit_price_width, 6, 'Units', ln=False)

   
        self.line(2, 102, 207, 102)  # Line from x=10 to x=200 at y=40
        # self.line(5, 230, 210, 230) # items table  end line 

        self.set_xy(157, 230)
        # self.cell(total_price_width, 6, 'Total (SGD)', ln=False)
        self.set_xy(157, 236)
        # self.cell(total_price_width, 6, 'GST (9%)', ln=False)
        self.set_xy(157, 242)
        # self.cell(total_price_width, 6, 'Total (SGD)', ln=False)

    def footer(self):

        if self.get_y() < 290:  # Check if we're far enough from the page bottom
            self.set_line_width(0.4)  # Adjust the value (in mm) to make it bolder (default is 0.2)
            self.set_font("helvetica", "B", 10)

            self.set_xy(2, 231)
            # self.cell(0, 6, 'Comments :', ln=False)
            self.line(2, 285, 207, 285) # footer above line

            self.set_xy(20, 285)
            self.cell(0, 6, 'Received By', ln=False)

            self.set_xy(140, 285)
            self.cell(0, 6, 'for Centroid Engineering Solutions', ln=False)

            self.set_xy(60, 289)
            self.cell(0, 6, 'This is a system generated DO no signature is required.', ln=False)

    def body(self):
        self.ln(10)  # space before content
        top_margin = 105  # your desired Y start position
        self.set_y(top_margin)
        self.set_font("helvetica", "", 10)

        description_width = 135
        item_width = 10
        qty_width = 10
        unit_price_width = 20
        max_y = 285
        uom_width = 15
        footer_space = 45

        for idx, item in enumerate(self.data_dict):
            calculated_heights = self._calculate_row_heights(item, description_width)
            description_height = calculated_heights['description_height']
            row_height = max(6, description_height)

            current_y = self.get_y()
            remaining_space = max_y - current_y
            is_last_item = (idx == len(self.data_dict) - 1)

            # Condition 1: Not last item, and current row doesn't fit → new page
            if not is_last_item and remaining_space < row_height:
                self._draw_vertical_lines_and_add_page( item_width, description_width, qty_width, unit_price_width, top_margin)

            # Condition 2: Last item, but not enough space for row + footer → new page
            elif is_last_item and remaining_space < row_height + footer_space:
                self._draw_vertical_lines_and_add_page( item_width, description_width, qty_width, unit_price_width, top_margin)

            current_y = self.get_y()
            self.set_xy(4, current_y)
            self.set_font("helvetica", "", 10)
            
            # Render nothing if item['index'] is None or the string "None"
            index_value = item['index']
            if index_value is None or str(index_value).strip().lower() == "none":
                index_to_render = ""
            else:
                index_to_render = str(index_value) # Ensure it's a string before passing to cell

            print("...item['index']...............", item['index'])
            self.cell(2 + item_width, 6, index_to_render, border=0)


            self._render_description(item, description_width, current_y, item_width)
            self._render_other_fields(item, current_y, item_width, description_width, unit_price_width, qty_width)
            self.set_y(current_y + row_height)

        if self.get_y() + footer_space <= max_y:
            self._draw_final_lines_and_totals(item_width, description_width, uom_width, qty_width, unit_price_width)
        else:
            self.add_page()
            self.header()
            self.set_y(top_margin)
            self._draw_final_lines_and_totals(item_width, description_width, uom_width, qty_width, unit_price_width)

    def _calculate_row_heights(self, item, description_width):
        description_text = item['item']
        description_height = self._calculate_description_height(description_text, description_width)
        print("............description_height.......",description_height)
        return {'description_height': description_height}

    def _calculate_description_height(self, description_text, description_width):
        
        lines = description_text.split('\n')
        total_height = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                total_height += 6  # Empty line height
                continue
                
            # Determine font size based on line type
            if line.startswith("Header -"):
                content = line.replace("Header -", "").strip()
                font_size = 11
            elif line.startswith("Subheader -"):
                content = line.replace("Subheader -", "").strip()
                font_size = 9
            elif line.startswith("Body -"):
                content = line.replace("Body -", "").strip()
                font_size = 10
            else:
                content = line
                font_size = 10
            
            # Set font temporarily to calculate width
            self.set_font("helvetica", "", font_size)
            
            # Calculate how many lines this content will wrap to
            if content:
                content_width = self.get_string_width(content)
                available_width = description_width - 2  # Account for margins
                lines_needed = max(1, int(content_width / available_width) + 1)
                total_height += lines_needed * 6
            else:
                total_height += 6
        
        return max(6, total_height)

    def _draw_vertical_lines_and_add_page(self, item_width, description_width,
                                        uom_width, qty_width, unit_price_width):

        # Draw vertical lines
        self.line(2 + item_width, 94, 2 + item_width, 250)
        self.line(27 + description_width, 94, 27 + description_width, 250)
        self.line(167 + qty_width, 94, 167 + qty_width, 250)
        self.line(187 + unit_price_width, 94, 187 + unit_price_width, 250)
        self.line(2, 250, 207, 250)
        
        # Add new page
        self.add_page()
        self.header()
        self.set_y(105)
        print(".........._draw_vertical_lines_and_add_page.......self.get_y()........",self.get_y() )

    def _render_description(self, item, description_width, current_y, item_width):
        description_x = 2 + item_width 
        description_y = current_y
        lines = item['item'].split('\n')
        self.set_xy(description_x, description_y)
        
        for line in lines:
            line = line.strip()
            
            if line.startswith("Header -"):
                content = line.replace("Header -", "").strip()
                self.set_font("helvetica", "B", 11)
            elif line.startswith("Subheader -"):
                content = line.replace("Subheader -", "").strip()
                self.set_font("helvetica", "B", 9)
            elif line.startswith("Body -"):
                content = line.replace("Body -", "").strip()
                self.set_font("helvetica", "", 10)
            else:
                content = line
                self.set_font("helvetica", "", 10)
            
            if content:
                self.set_x(description_x)
                self.multi_cell(description_width, 6, content, 0, 'L')

    def _render_other_fields(self, item, current_y, item_width,description_width, qty_width, unit_price_width):
            """Render the other fields (UOM, Quantity, Unit Price, Total) aligned to current_y"""
            
            self.set_font("helvetica", "", 10)
            self.set_y(current_y)
            self.set_x(2 + item_width + description_width + 15)
            self.set_font("helvetica", "", 10)
            
            quantity_value = item['quantity']
            if quantity_value is None or str(quantity_value).strip().lower() == "none":
                quantity_to_render = ""
            else:
                quantity_to_render = str(quantity_value)
            self.cell(qty_width-5, 6, quantity_to_render, 0, 0, 'R', False)

            # ---------- Unit Price ----------
            self.set_x(2 + item_width+7 + description_width + qty_width + 22)
            # Align item['Unit'] to the right, render nothing if None or "None" string
            unit_value = item['Unit']
            if unit_value is None or str(unit_value).strip().lower() == "none":
                unit_to_render = ""
            else:
                unit_to_render = str(unit_value)
            self.cell(unit_price_width, 6, unit_to_render, 0, 0, 'R', False)

    def _draw_final_lines_and_totals(self, item_width, description_width,uom_width, qty_width, unit_price_width ):
        """Draw final lines and render totals section"""
        
        # Draw vertical lines
        self.line(2 + item_width, 94, 2 + item_width, 250)
        self.line(27 + description_width, 94, 27 + description_width, 250)
        self.line(167 + qty_width, 94, 167 + qty_width, 250)
        self.line(187 + unit_price_width, 94, 187 + unit_price_width, 250)
        self.line(2, 250, 207, 250)


        # Warranty and Remarks
        self.set_font("helvetica", "B", 10)
        self.set_xy(2, 250)
        self.cell(0, 6, 'Warranty: ', ln=False)
        self.set_xy(2, 260)
        self.cell(0, 6, 'Remarks: ', ln=False)

        self.set_font("helvetica", "", 10)
        self.set_xy(21, 250)
        self.cell(0, 6, self.do_details['Warranty'], ln=True)
        self.set_xy(21, 260)
        self.cell(0, 6, self.do_details['Remarks'], ln=True)


        ces_stamp_img = os.path.join('static', 'ces_stamp.png')  
        sign_img = os.path.join('static', f"{self.do_details['created_by']}.png")

        # Try to add the CES Stamp image
        try:
            self.image(ces_stamp_img, 145, 255, 30)  # Only width is specified, height is auto-scaled.
        except Exception as e:
            print(f"Error loading image {ces_stamp_img}: {e}")

        # Try to add the signature image
        try:
            self.image(sign_img, 170, 265, 30)  # Only width is specified, height is auto-scaled.
        except Exception as e:
            print(f"Error loading image {sign_img}: {e}")


@app.route('/delete_prj_do', methods=['POST'])
@login_required
def delete_prj_do():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "Unauthorized access"}), 401

    data = request.get_json()
    do_number = data.get('do_number')

    if not do_number:
        return jsonify({"success": False, "message": "DO number is required"}), 400

    db = get_database()
    cursor = db.cursor()

    cursor.execute("SELECT proj_no FROM created_do WHERE do_number = ?", (do_number,))
    result = cursor.fetchone()

    if result is None:
        return jsonify({"success": False, "message": f"DO {do_number} not found"}), 404

    proj_no = result[0]

    cursor.execute("DELETE FROM do_items WHERE do_number = ?", (do_number,))
    cursor.execute("DELETE FROM created_do WHERE do_number = ?", (do_number,))
    db.commit()

    return jsonify({"success": True, "message": f"DO {do_number} deleted successfully"})

@app.route('/get_do_details', methods=['POST'])
def get_do_details():
    project_id = request.json.get('project_id')
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project = cursor.fetchone()
    from datetime import datetime

    if project is None:
        return jsonify({'error': 'Project not found'}), 404
    if project['status'] == 'Closed':
        return jsonify({'error': 'Project is closed. Cannot create DO'}), 400

    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")
    project_details = { 'project_id': project_id, 'client': project['client'], 'po_number': project['po_number'], 
                       'delivery_address': project['delivery_address'], 'do_date': formatted_date}
    return jsonify(project_details)

@app.route('/get_do_details_toview')
def get_do_details_toview():
    DO_no = request.args.get('DO_no')
    db = get_database()
    cursor = db.cursor()

    # Fetch the DO details
    do_details = cursor.execute("SELECT * FROM created_do WHERE do_number = ?", (DO_no,)).fetchone()
    if not do_details:
        return jsonify({'success': False, 'message': 'Delivery Order not found'})

    # Fetch all associated DO items
    do_items = cursor.execute("SELECT * FROM do_items WHERE do_number = ?", (DO_no,)).fetchall()

    return jsonify({
        'success': True,
        'do_details': dict(do_details) if do_details else {},
        'do_items': [dict(row) for row in do_items] if do_items else []
    })

@app.route('/prj_planner', methods=['GET', 'POST'])
@login_required
def prj_planner():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.args.get('project_id', type=int)
    user_access = get_employee_access_control(user['name'])


    user_access = get_employee_access_control(user['name'])
    cursor.execute('SELECT username FROM admin_user WHERE register = 1')

    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 



    cursor.execute('SELECT * FROM user_tasks ORDER BY due_date')
    tasks = [
        {
            'id': row[0],
            'task_name': row[1],
            'assigend_to': row[2],
            'bucket': row[3],
            'progress': row[4],
            'priority': row[5],
            'start_date': row[6],
            'due_date': row[7],
            'label': row[8],
            'notes': row[9],
            'checklist': row[10],
            'attachemnt_file': row[11],
            'created_by': row[12],
            'created_date': row[13],
        }
        for row in cursor.fetchall()
    ]


    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 


    cursor.execute("SELECT DISTINCT bucket FROM user_tasks WHERE bucket IS NOT NULL AND bucket != ''")
    buckets = sorted(set([row[0] for row in cursor.fetchall()]))

    cursor.execute("SELECT DISTINCT label FROM user_tasks WHERE label IS NOT NULL AND label != ''")
    labels = sorted(set([row[0] for row in cursor.fetchall()]))
    print("..........buckets...........",buckets)
    print("..........labels...........",labels)

    return render_template('admin_templates/projects/prj_planner.html',
                        is_pm=is_pm, department_code=department_code,buckets=buckets,labels=labels,
                        user_access=user_access, user=user,usernames=usernames,tasks=tasks,
                        project_id=project_id, project_details=project_details )

@app.route('/project_po', methods=['GET', 'POST'])
@login_required
def project_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.args.get('project_id', type=int)
    total_po_sum1  = 0

    if request.method == 'POST':
        # Get the ID of the item to delete from the form
        PO_Delete = request.form.get('Delete')

        # Get the PO_no from the created_po table using the ID before deletion
        cursor = db.cursor()
        cursor.execute('SELECT PO_no FROM created_po WHERE id = ?', (PO_Delete,))
        result = cursor.fetchone()
        
        if result:
            PO_no = result[0]  # Extract the PO_no from the result

            # Step 2: Set the total to '0' in both tables instead of deleting
            cursor.execute('UPDATE po_items SET total = "0" WHERE PO_number = ?', (PO_no,))
            cursor.execute('UPDATE created_po SET total = "0" WHERE id = ?', (PO_Delete,))

            # Optional: Set the status of the PO to indicate it's reset (optional)
            cursor.execute('UPDATE created_po SET status = "Canceled" WHERE id = ?', (PO_Delete,))

            flash(f'PO and related items with PO number {PO_no} have been successfully Canceled.', 'po_delete')
        else:
            cursor.execute('UPDATE created_po SET total = "0" WHERE id = ?', (PO_Delete,))
            
            flash('PO not found. Nothing was deleted.', 'error')

        db.commit()

    # Fetch all created PR records
    project_id = request.args.get('project_id', type=int)
    cursor = db.execute('SELECT * FROM created_po WHERE project_id = ? ORDER BY id DESC',(project_id,))
    created_po = cursor.fetchall()
    # Initialize an empty DataFrame to store the main data
    rows = []

    for pr in created_po:
        pr_id = pr[0]
        pr_no = pr[1]
        project_id = pr[2]
        supplier_name = pr[3]
        pr_date = pr[5]
        created_by = pr[6]
        Code = pr[8]
        status = pr[14]
        Approved_by = pr[23]
        PR_no_ref = pr[24]
        PO_Issued_by = pr[25]
        do_staus = pr[26]
    
        cursor.execute('SELECT item, quantity, uom, Unit_Price, total, excepted_date, status FROM po_items WHERE PO_number = ?', (pr_no,))
        items = cursor.fetchall()
        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4], 'excepted_date':item[5], 'status':item[6] })

        total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
        total_po_sum1 += total_price_sum1  # Add to the cumulative total sum
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)


        # Append the main row to the rows list
        rows.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by, 'Approved_by': Approved_by,
                      'PR_no_ref':PR_no_ref, 'PO_Issued_by':PO_Issued_by, 'do_staus': do_staus, 'Status': status,'PR_Total': total_price_sum,'Sub_DF': pd.DataFrame(sub_df_data) })
    
    total_po_sum = locale.format_string("%0.2f", total_po_sum1, grouping=True)
    # Convert rows to a pandas DataFrame
    grouped_df = pd.DataFrame(rows)
    user_access = get_employee_access_control(user['name'])
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 
    return render_template('admin_templates/projects/project_po.html',is_pm=is_pm, department_code=department_code, created_po=created_po,user=user, 
                           project_details=project_details,user_access=user_access,project_id=project_id,grouped_df=grouped_df,total_sum=total_po_sum)

@app.route('/generate_prj_pr', methods=['POST'])
def generate_prj_pr():
    from datetime import datetime
    import re
    db = get_database()
    cursor = db.cursor()
    user = get_current_user()

    project_id = request.form.get('project_id', type=int)
    Supplier_Name = request.form.get('Supplier_Name')
    query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
    cursor.execute(query, (Supplier_Name,))
    result = cursor.fetchone()

    if result:
        Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
        Supplier_address3 = f"{country}, {city} - {postcode}"

    Attn = request.form.get('Attn')
    leat_time = request.form.get('leat_time')
    Unit = request.form.get('Unit')
    leat_time =  str(leat_time) + ' ' +  Unit
    Contact = request.form.get('Contact')
    phone_number = request.form.get('phone_number')
    PR_Date = request.form.get('PR_Date') 
    Quote_Ref = request.form.get('Quote_Ref')
    Expenses = request.form.get('code_number')
    comments = request.form.get('comments')
    project_id = request.form.get('project_id')
    gst_option = request.form.get('gst_option')
    part_nos = request.form.getlist('part_no[]')
    description_headers = request.form.getlist('description_header[]')
    description_subheaders = request.form.getlist('description_subheader[]')
    description_bodys = request.form.getlist('description_body[]')
    uoms = request.form.getlist('uom[]')
    excepted_dates = request.form.getlist('excepted_date[]') 
    quantities = request.form.getlist('quantity[]')
    unit_prices = request.form.getlist('unit_price[]')
    Delivery = request.form.get('Delivery')
    Address_Line1 = request.form.get('Address_Line1')
    Address_Line2 = request.form.get('Address_Line2')
    Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
    Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
    Exchange_rate = request.form.get('Exchange_rate').upper() 
    existing_pr = request.form.get('existing_pr')
    Discount_percent = float(request.form.get('Discount') or 0)

    if existing_pr:
        
        current_date = datetime.now()
        existing_pr = existing_pr.strip()
        pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
        match = pattern.match(existing_pr)
        if match:
            base_pr_number = match.group(1)
            suffix = match.group(3)
            if suffix:
                new_suffix = int(suffix) + 1
            else:
                new_suffix = 1
            New_PR_no = f"{base_pr_number}({new_suffix})"
        else:
            # If the PR number format is incorrect
            New_PR_no = "Invalid PR number format"
    
    else:

        cursor.execute("SELECT MAX(id) FROM created_pr")
        result = cursor.fetchone()
        if result and result[0] is not None:
            max_pr = int(result[0])
        else:
            max_pr = 0
        
        sequential_number = max_pr + 1
        New_PR_no = f"{project_id}-{Expenses}-{sequential_number:04}"

    attachment = request.files.get('attachment')  # Get the attachment from the form

    if attachment:
        upload_dir = 'docment_data/PR Quotes'
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir) 

        file_name, file_extension = os.path.splitext(attachment.filename) 
        new_filename = f"{New_PR_no}{file_extension}" 
        # print("...........new_filename......",new_filename)
        filename = os.path.join(upload_dir, new_filename)
        attachment.save(filename)
        # print(f"File uploaded successfully: {filename}")
    
    else:
        new_filename = None  # No file uploaded
        print("No file uploaded.")


    if existing_pr:

        pr_data = cursor.execute('SELECT * FROM created_pr WHERE PR_no = ?', (existing_pr,)).fetchone()
        columns = [desc[0] for desc in cursor.description]
        for col, val in zip(columns, pr_data):
            print(f"{col}: {val}")

        cursor.execute('''INSERT INTO created_pr (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery, 
            Address_Line1, Address_Line2, Payment_Terms, Currency, Exchange_rate, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, 
            leat_time, comments, status, original_creater, filename, Discount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (New_PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, Contact, Quote_Ref, pr_data['Expenses'] , Delivery, Address_Line1, Address_Line2,
            Payment_Terms, Currency, Exchange_rate, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments, 'Created',
            user['name'], pr_data['filename'], Discount_percent ))

        db.commit()
        Message = "PR Updated successfully"
    
    else:

        cursor.execute('''INSERT INTO created_pr (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery, 
                    Address_Line1, Address_Line2, Payment_Terms, Currency, Exchange_rate, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, 
                    leat_time, comments, status, original_creater, filename, Discount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                    (New_PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, Contact, Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2,
                    Payment_Terms, Currency, Exchange_rate, Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments, 'Created',
                    user['name'],new_filename ,Discount_percent))
        db.commit()
        Message = "PR Created successfully"

    cursor.execute("SELECT GST FROM GST ORDER BY Date DESC LIMIT 1")
    latest_gst = cursor.fetchone()  # Fetch the first result
    latest_gst_value = latest_gst[0] if latest_gst else 1 
    items = []
    for idx, (part_no, uom, excepted_date, quantity, unit_price) in enumerate(zip(part_nos, uoms, excepted_dates, quantities, unit_prices)):
        # Prepare multi-line description
        lines = []
        if idx < len(description_headers) and description_headers[idx].strip():
            lines.append(f"Header - {description_headers[idx].strip()}")
        if idx < len(description_subheaders) and description_subheaders[idx].strip():
            lines.append(f"Subheader - {description_subheaders[idx].strip()}")
        if idx < len(description_bodys) and description_bodys[idx].strip():
            lines.append(f"Body - {description_bodys[idx].strip()}")
        
        description = "\n".join(lines)
        print(".........description.................!!!!!\n",description)

        total = float(quantity) * float(unit_price)
        rounded_total = round(total, 2)

        item = {
            'project_id': project_id,
            'pr_number': New_PR_no,
            'part_no': part_no,
            'description': description,
            'uom': uom,
            'quantity': float(quantity),
            'unit_price': float(unit_price),
            'total': rounded_total,
            'excepted_date': excepted_date,
        }

        item['gst'] = latest_gst_value if gst_option == 'Yes' else 1
        print("...............item....................",item)
        items.append(item)

    if items:
        for item in items:
            cursor.execute("""INSERT INTO pr_items ( project_id, pr_number, Part_No,item,  quantity,  uom,  Unit_Price, GST,  total, excepted_date, status)  
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                (item['project_id'],item['pr_number'],item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'],item['gst'], item['total'], item['excepted_date'], 'Open' ))
        db.commit()


        if  existing_pr:
            cursor.execute('DELETE FROM created_pr WHERE PR_no = ?', (existing_pr,))
            cursor.execute('DELETE FROM pr_items WHERE pr_number = ?', (existing_pr,))
            db.commit()



        cursor.execute("SELECT pm, project_name FROM projects WHERE id = ?", (project_id,))
        result = cursor.fetchone()
        db.commit()

        if result:
            pm = result[0] #pm
            user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (pm,))
            mail_to_row = user_cur.fetchone()
            if mail_to_row:
                mail_to = mail_to_row['name']
            else:
                mail_to = 'sairam@gmail.com'
        
        project_name = result[1] #project name
        created_by = user['name']

        query = """  SELECT name, username FROM admin_user WHERE department_code IN (14, 1000) OR secondary_role_code = 14; """
        cursor.execute(query)
        results = cursor.fetchall()
        employee_emails = [row[0] for row in results] 
        if mail_to not in employee_emails:  
            employee_emails.append(mail_to)

        import re
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        valid_emails = [email for email in employee_emails if re.match(email_regex, email)]
        if valid_emails and Message == "PR Created successfully" :
            print("..............valid_emails............",valid_emails)

            # email_thread = threading.Thread( target=send_created_pr_email, args=(employee_emails, project_name, project_id, created_by, New_PR_no))
            # email_thread.start()

        return jsonify({'message': Message})

    
    return jsonify({'message': 'PR Not Created.'})

@app.route("/get_part_history")
def get_part_history():
    part_no = request.args.get("part_no")
    if not part_no:
        return jsonify([])

    db = get_database()
    cursor = db.cursor()

    query = """
        SELECT 
            pi.Part_No, pi.item, pi.Unit_Price, pi.quantity, pi.uom,
            cp.Supplier_Name, cp.PO_Date, cp.Currency, cp.Exchange_rate
        FROM po_items pi
        JOIN created_po cp ON pi.PO_number = cp.PO_no
        WHERE pi.Part_No = ?
        ORDER BY cp.PO_Date DESC
        LIMIT 10;
    """
    cursor.execute(query, (part_no,))
    rows = cursor.fetchall()

    # Column names
    keys = ["Part_No", "item", "Unit_Price", "quantity", "uom", "Supplier_Name", "PO_Date", "Currency", "Exchange_rate"]

    # Convert to list of dicts
    data = [dict(zip(keys, row)) for row in rows]

    return jsonify(data)

def send_created_pr_email(valid_emails, project_name, project_id, created_by, PR_no):
    """Send PR Created emails asynchronously."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    filtered_emails = [email for email in valid_emails if re.match(email_regex, email)]

    if filtered_emails:
        PR_Created_Notification(filtered_emails, project_name, project_id, created_by, PR_no)

@app.route("/pr_to_edit/<pr_no>")
def pr_to_edit(pr_no):
    db = get_database()
    cursor = db.cursor()
    # Get PR header
    pr = db.execute("SELECT * FROM created_pr WHERE PR_no = ?", (pr_no,)).fetchone()
    if not pr:
        return jsonify({"error": "PR not found"}), 404

    # Optionally: Get PR items (if you want to fill them)
    items = db.execute("SELECT * FROM pr_items WHERE pr_number = ?", (pr_no,)).fetchall()

    # Convert row objects to dictionaries
    pr_data = dict(pr)
    pr_data["items"] = [dict(item) for item in items]  # Optional if you want to show items too

    filename = pr_data.get("filename")
    print(".....filename........",filename)

    if filename:
        pr_data["attachment_url"] = url_for('static', filename=f'document_data/PR Quotes/{filename}')


    return jsonify(pr_data)

@app.route('/docment_data/PR Quotes/<path:filename>')
def view_prj_pr_file(filename):
    # directory = os.path.abspath(r'docment_data\PR Quotes')
    directory = os.path.abspath('/home/CES/docment_data/PR Quotes')

    # List of common file extensions
    extensions = [
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Images
    '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',  # Documents and spreadsheets
    '.html', '.htm', '.xml', '.json',  # Web and data files
    '.zip', '.tar', '.gz', '.rar',  # Archive files
    '.mp3', '.wav', '.ogg',  # Audio files
    '.mp4', '.avi', '.mkv', '.mov', '.webm',  # Video files
    '.svg', '.eps', '.ai',  # Vector images
    '.psd', '.indd',  # Adobe files (Photoshop, InDesign)
    '.epub', '.mobi', '.azw3',  # Ebook formats
    '.pptx', '.key',  # Presentation files
    '.xlsx', '.ods',  # Spreadsheet formats
    '.json', '.yaml',  # Configuration and data files
    '.md', '.rst',  # Markup files
    '.exe', '.msi', '.dmg',  # Executables and install files
    ]

    
    # Try each extension until we find the correct one
    for ext in extensions:
        file_path = os.path.join(directory, filename )
        print(f"Checking file path: {file_path}")
        
        if os.path.exists(file_path):
            return send_from_directory(directory, filename, as_attachment=False)
    
    return "File not found", 404

@app.route('/delete_prj_pr/<pr_no>', methods=['DELETE'])
def delete_prj_pr(pr_no):
    db = get_database()
    cursor = db.cursor()

    # Delete from pr_items
    cursor.execute('DELETE FROM pr_items WHERE pr_number = ?', (pr_no,))

    # Delete from created_pr
    cursor.execute('DELETE FROM created_pr WHERE PR_no = ?', (pr_no,))

    db.commit()
    return jsonify({'success': True, 'message': f'PR {pr_no} deleted successfully.'})

@app.route('/project_pr', methods=['GET', 'POST'])
@login_required
def project_pr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])    
    project_id = request.args.get('project_id', type=int)
    cursor = db.cursor()
    PR_no = "Auto Generation"
    cursor.execute('SELECT display_name FROM vendors_details')
    # Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
    Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    user_access = get_employee_access_control(user['name'])

    cursor = db.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC', (project_id,))
    pr_query = cursor.fetchall()

    columns = [desc[0] for desc in cursor.description]
    pr_data = [dict(zip(columns, pr)) for pr in pr_query]

    for row in pr_data:
        pr_no = row['PR_no']
        project_id = int(row.get('project_id', 0)) if row.get('project_id') else None

        # Get PM info
        cursor.execute("SELECT pm FROM projects WHERE id = ?", (project_id,))
        pm_result = cursor.fetchone()
        row['pm'] = 'Yes' if pm_result and user['name'] == pm_result[0] else 'No'

        # Get total and GST percent from pr_items
        cursor.execute("SELECT SUM(total), AVG(GST) FROM pr_items WHERE pr_number = ?", (pr_no,))
        total, gst_percent = cursor.fetchone()
        total = float(total) if total else 0
        gst_percent = float(gst_percent) if gst_percent else 0

        # Get exchange rate (default to 1.0 if missing)
        exchange_rate = float(row.get('Exchange_rate', 1.0) or 1.0)

        # Calculate GST amount and total with exchange rate
        gst_amount = (total * gst_percent / 100) if gst_percent and gst_percent != 1 else 0

        total_with_gst = total + gst_amount

        # Apply exchange rate
        row['amount'] = round(total / exchange_rate, 2)
        row['GST'] = round(gst_amount / exchange_rate, 2)
        row['total'] = round(total_with_gst / exchange_rate, 2)
        row['id'] = row.get('id', None)


    # ✅ Correct list variable
    grouped_df = pd.DataFrame(pr_data)

    # ✅ Check if 'id' exists before sorting
    if 'id' in grouped_df.columns:
        grouped_df = grouped_df.sort_values(by='id', ascending=False)
    else:
        print("Warning: 'id' column not found in DataFrame.")

    user_access = get_employee_access_control(user['name'])
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 
    cursor.execute(''' SELECT GST FROM GST WHERE Date = (SELECT MAX(Date) FROM GST);''')
    latest_gst_value = cursor.fetchone()
    gst = latest_gst_value[0]
    return render_template('admin_templates/projects/project_pr.html', usernames=usernames,current_date=formatted_date, is_pm=is_pm, 
                           department_code=department_code, user_access=user_access, Supplier_Names=Supplier_Names, grouped_df=grouped_df,
                          project_details=project_details,PR_no=PR_no, user=user, project_id=project_id, gst=gst)

@app.route('/pr_view', methods=['GET', 'POST'])
@login_required
def pr_view():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    total_pr_sum1  = 0

    # Fetch all created PR records
    project_id = request.args.get('project_id', type=int)

    # Fetch all PR_nos from created_pr for the given project_id
    cursor.execute('SELECT PR_no FROM created_pr WHERE project_id = ?', (project_id,))
    pr_nos = cursor.fetchall()

    # Iterate through each PR_no and check for corresponding items in pr_items
    for pr_no in pr_nos:
        cursor.execute('SELECT COUNT(*) FROM pr_items WHERE pr_number = ? AND project_id = ?', (pr_no[0], project_id))
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.execute('DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?', (pr_no[0], project_id))

    # Commit the changes to the database
    db.commit()

    cursor = db.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC',(project_id,))
    created_pr = cursor.fetchall()

    # Initialize an empty DataFrame to store the main data
    rows = []
    # Loop through each PR in created_pr
    for pr in created_pr:
        pr_id = pr[0]
        pr_no = pr[1]
        pr_date = pr[5]
        project_id = pr[2]
        supplier_name = pr[3]
        created_by = pr[6]
        status = pr[14]
        Code = pr[8] 
        Approved_by = pr[23] 


        # Fetch items for the current PR from pr_items table
        cursor.execute('SELECT id, item, quantity, uom, Unit_Price, total,excepted_date,status FROM pr_items WHERE pr_number = ?', (pr_no,))
        items = cursor.fetchall()

        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'ID': item[0], 'Description': item[1], 'QTY': item[2], 'UOM': item[3], 
                                'Unit_Price': item[4], 'Total_Price': item[5], 'excepted_date': item[6],'status': item[7] })

        total_price_sum1 = round(sum([float(item[5]) for item in items]), 2)
        total_pr_sum1 += total_price_sum1  # Add to the cumulative total sum

        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
        # Append the main row to the rows list
        rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,
                     'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum, 'Approved_by': Approved_by,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    # Convert rows to a pandas DataFrame
    total_pr_sum = locale.format_string("%0.2f", total_pr_sum1, grouping=True)
    print(f"Total sum ...........................of all PRs: {total_pr_sum}")


    grouped_df = pd.DataFrame(rows)
    user_access = get_employee_access_control(user['name'])

    if request.method == 'POST':
        Approve = request.form.get('Approve')
        Issued = request.form.get('Issued')
        Delete = request.form.get('Delete')
        Print = request.form.get('Print')
        project_id = request.args.get('project_id', type=int)
        Update = request.form.get('Update')

        db = get_database()
        cursor = db.cursor()

        if Approve:
            cursor.execute('UPDATE created_pr SET status = ?, approved_by = ? WHERE id = ?', ('Approved',user['name'], Approve)) 
            cursor.execute("SELECT PR_no , project_id, created_by, PR_Date FROM created_pr WHERE id = ?", (Approve,))
            result = cursor.fetchone()

            if result:
                PR_no, project_id, created_by, pr_date = result 

                # Initialize an empty set for all email addresses
                all_emails_set = set()

                # Get pm and project members from the projects table
                cursor = db.execute("SELECT pm, project_members FROM projects WHERE id = ?", (project_id,))
                project_row = cursor.fetchone()
                
                if project_row:
                    pm = project_row[0]  # Get pm
                    project_members = project_row[1]  # Get project members
                    # Ensure project_members is not None
                    if project_members is None:
                        project_members = ''  # Assign an empty string to avoid AttributeError
                    all_members = [pm] + project_members.split(',')
                    all_members = set(all_members)
                    placeholders = ','.join('?' for _ in all_members)  # Create placeholders for SQL query
                    cursor.execute(f"SELECT name FROM admin_user WHERE username IN ({placeholders})", list(all_members))
                    member_emails = [row[0] for row in cursor.fetchall()]
                    for email in member_emails:
                        if email not in all_emails_set:
                            all_emails_set.add(email)

                    # Fetch created_by email
                    user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (created_by,))
                    created_by_row = user_cur.fetchone()
                    if created_by_row:
                        created_by_email = created_by_row['name']
                        if created_by_email not in all_emails_set:
                            all_emails_set.add(created_by_email)
                    else:
                        # Add default email if created_by email is not found
                        if 'sairam@gmail.com' not in all_emails_set:
                            all_emails_set.add('sairam@gmail.com')

                    # Fetch emails of employees with access control as 'pur_purchaser'
                    # query = """ SELECT au.name FROM access_control ac JOIN admin_user au ON ac.Employee_ID = au.username WHERE ac.pur_purchaser = 'On'; """
                    query = """SELECT name, username FROM admin_user WHERE department_code IN (14, 1000) OR secondary_role_code IN (14, 1000);"""
                    cursor.execute(query)
                    results = cursor.fetchall()

                    # Add employee emails to the set if they don't already exist
                    for row in results:
                        email = row[0]
                        if email not in all_emails_set:
                            all_emails_set.add(email)

                    # Convert the set to a list for further use
                    all_emails = list(all_emails_set)

                    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
                    # Filter valid email addresses
                    valid_emails = [email for email in all_emails if re.match(email_regex, email)]
                    # Optionally print or use the valid_emails list
                    print("Valid Emails:", valid_emails)

                    # Send notification
                    approved_by = user['name']
                    # PR_Approval_Notification(valid_emails, pr_date, project_id, approved_by, created_by, PR_no)

            else:
                print("No data found for the given PR ID")

        if Issued:

            cursor.execute('UPDATE created_pr SET status = ? WHERE id = ?', ('Processed', Issued))
            cursor.execute('SELECT * FROM created_pr WHERE id = ?', (Issued,))
            pr_details = cursor.fetchone()
            (id, PR_no, project_id, Supplier_Name, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery,  Address_Line1, Address_Line2, Payment_Terms, Currency, status,
              total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,comments,approved_by,original_creater) = pr_details
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d-%m-%y")
            cursor.execute("SELECT MAX(id) FROM created_po")
            result = cursor.fetchone()

            if result and result[0] is not None:
                max_pr = int(result[0])
            else:
                max_pr = 0

            sequential_number = max_pr + 1
            PO_no = f"{project_id}-{Expenses}-{sequential_number:04}"
            cursor.execute('''SELECT COUNT(*) FROM created_po  WHERE project_id = ?  AND Supplier_Name = ?  AND phone_number = ?  AND PO_Date = ? AND created_by = ?  AND Quote_Ref = ? 
                            AND Expenses = ?  AND total = ?''',  (project_id, Supplier_Name, phone_number, formatted_date, created_by, Quote_Ref, Expenses, total))
            exists = cursor.fetchone()[0]
            if exists == 0:
                cursor.execute('''INSERT INTO created_po (PO_no, project_id, Supplier_Name, phone_number, PO_Date, created_by, Quote_Ref, Expenses, Delivery, Address_Line1, 
                            Address_Line2, Payment_Terms, Currency, status, total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,
                               comments, approved_by, PR_no_ref, PO_Issued_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                                ( PO_no, project_id, Supplier_Name, phone_number, formatted_date, created_by, Quote_Ref, Expenses, Delivery, 
                                Address_Line1, Address_Line2, Payment_Terms, Currency, 'Issued', total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,comments, 
                                approved_by,PR_no,user['name'] ))

                cursor.execute("SELECT * FROM pr_items WHERE pr_number = ? AND project_id = ?", (PR_no, project_id))
                temp_items = cursor.fetchall()

                # Insert fetched items into pr_items
                for item in temp_items:
                    cursor.execute("INSERT INTO po_items (project_id, PO_number, Part_No, item, quantity, uom, Unit_Price, total, GST) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (item['project_id'], PO_no, item['Part_No'], item['item'], item['quantity'], item['uom'], item['Unit_Price'], item['total'],item['GST']))

                    total_sum = float(item['total'].replace(',', ''))
                    cost = item['quantity'] * item['Unit_Price']
                    cursor.execute("INSERT INTO manual_entry (project_id, username, department_code, cost, gst_value, total, cost_center_id) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                   (project_id, user['name'], Expenses, cost , item['GST'], total_sum,PO_no ))
                    

            # Initialize a set to hold all unique emails
            all_emails_set = set()

            # Get pm and project members from the projects table
            cursor = db.execute("SELECT pm, project_members FROM projects WHERE id = ?", (project_id,))
            project_row = cursor.fetchone()

            if project_row:
                pm = project_row[0]  # Get pm
                project_members = project_row[1]  # Get project members
                # Ensure project_members is not None
                if project_members is None:
                    project_members = ''  # Assign an empty string to avoid AttributeError

                # Add pm and project members to a set to remove duplicates
                all_members = {pm} | set(project_members.split(','))

                # Fetch emails for pm and project members from the admin_user table
                placeholders = ','.join('?' for _ in all_members)  # Create placeholders for SQL query
                cursor.execute(f"SELECT name FROM admin_user WHERE username IN ({placeholders})", list(all_members))
                member_emails = {row[0] for row in cursor.fetchall()}

                # Add member emails to the all_emails_set
                all_emails_set.update(member_emails)


            query = """ SELECT name, username  FROM admin_user  WHERE department_code IN (14, 1000) OR secondary_role_code IN (14, 1000);"""

            cursor.execute(query)
            results = cursor.fetchall()

            # Add employee emails to the set
            all_emails_set.update({row[0] for row in results})

            # Get name for the created_by username
            created_by_user = db.execute('SELECT name FROM admin_user WHERE username = ?', (created_by,)).fetchone()
            if created_by_user:
                all_emails_set.add(created_by_user[0])

            # Get name for the approved_by username
            approved_by_user = db.execute('SELECT name FROM admin_user WHERE username = ?', (approved_by,)).fetchone()
            if approved_by_user:
                all_emails_set.add(approved_by_user[0])

            # Convert the set to a list for further use
            all_emails = list(all_emails_set)

            # Optionally print the names
            print("Names List:", all_emails)

            # Send notification
            issued_by = user['name']

            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            # Filter valid email addresses
            valid_emails = [email for email in all_emails if re.match(email_regex, email)]
            # Optionally print or use the valid_emails list
            print("Valid Emails:", valid_emails)
            
            # PR_Processed_Notification(valid_emails, PR_no, project_id, issued_by, PO_no)

        if Delete:
            cursor.execute('SELECT PR_no FROM created_pr WHERE id = ?', (Delete,))
            pr_no = cursor.fetchone()[0]
            cursor.execute('DELETE FROM created_pr WHERE id = ?', (Delete,))
            cursor.execute('DELETE FROM pr_items WHERE pr_number = ?', (pr_no,))
            db.commit()
            flash(f'PR and related items with PR number {pr_no} have been successfully deleted.', 'pr_delete_message')


    search_values = [0,0,'none']

    cursor.execute('SELECT PR_no FROM created_pr ORDER BY id DESC ')
    PR_Numbers = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT project_id FROM created_pr ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Expenses FROM created_pr ORDER BY id DESC')
    Expenses = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Supplier_Name FROM created_pr ORDER BY id DESC')
    Supplier_Names = [row[0] for row in cursor.fetchall()]

    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 


    return render_template('admin_templates/projects/pr_view.html', grouped_df=grouped_df, user=user,project_id=project_id, department_code=department_code, is_pm=is_pm,
                          total_sum=total_pr_sum,project_details=project_details,user_access=user_access, PR_Numbers=PR_Numbers,project_ids=project_ids,Expenses=Expenses,Supplier_Names=Supplier_Names,search_values=search_values)


@app.route('/project_details_page/<int:id>', methods=['GET', 'POST'])
@login_required
def project_details_page(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))


        # Utility function for department categorization
    def categorize_department(department_code):
        try:
            department_code = int(department_code)
        except ValueError:
            return 'Invalid'
        categories = {
            'Resources': list(range(1000, 1999)) + list(range(10, 101)),  # Add range 10-100 to Resources
            'Material': range(2000, 2999),
            'Sub Contract': range(3000, 3999),
            'Optional': range(4000, 4999),
        }

        # Check for matching category
        for category, code_range in categories.items():
            if department_code in code_range:
                return category

        # Adjust condition so that department_code between 10 and 100 is not categorized as 'Others'
        if department_code < 1000 and not (10 <= department_code <= 100):
            return 'Others'
        else:
            return 'something'

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    
    # Get projectId from query parameters
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (id,))
    project_details = cursor.fetchone() 
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    pr_data =  get_pr_data(id)
    po_data, po_total_sum = get_po_data(id)

    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE project_id = ?",(id,))
    PR_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_po WHERE project_id = ?",(id,))
    PO_count = cursor.fetchone()[0]

    from datetime import datetime
    current_year = datetime.now().strftime('%Y')[2:]

    cursor.execute(""" SELECT Supplier_Name, COUNT(*) AS supplier_count FROM created_po WHERE project_id = ? GROUP BY Supplier_Name ORDER BY supplier_count DESC LIMIT 1;""", (id,))
    most_visited_supplier = cursor.fetchone()
    most_visited_supplier_name = most_visited_supplier[0] if most_visited_supplier else "No data"
    most_visited_supplier_count = most_visited_supplier[1] if most_visited_supplier else 0

    query = """SELECT SUM(totalhours) AS total_hours_sum, SUM(overtime_1_5) AS total_overtime_1_5_sum, SUM(overtime_2_0) AS total_overtime_2_0_sum FROM workingHours WHERE projectID = ?;"""
    cursor.execute(query, (id,))
    result = cursor.fetchone()
    # Store the sums in variables
    total_hours_sum = result[0] if result[0] is not None else 0.0
    total_overtime_1_5_sum = result[1] if result[1] is not None else 0.0
    total_overtime_2_0_sum = result[2] if result[2] is not None else 0.0
    insights = { "total_hours_sum": total_hours_sum,
        "ouvet_time": total_overtime_1_5_sum + total_overtime_2_0_sum, "PR_count": PR_count, "PO_count": PO_count,
        "most_visited_supplier_count": most_visited_supplier_count, "most_visited_supplier_name" : most_visited_supplier_name, }

    # Generate summaries
    def process_summary(summary_data):
        data = [{ 'department_code': dept_code,  'total_adjusted_cost': dept_data.get('total_adjusted_cost', 0.0), 'budget_for_hours': dept_data.get('budget_for_hours', 0.0),
                'balance': dept_data.get('budget_for_hours', 0.0) - dept_data.get('total_adjusted_cost', 0.0)} for dept_code, dept_data in summary_data.items()]
        df = pd.DataFrame(data)
        return df

    working_hours_cost = get_department_cost_summary(id)
    simplified_summary = working_hours_cost.get('simplified_summary', {})
    final_summary_df = process_summary(simplified_summary)
    final_summary_df['Description'] = final_summary_df['department_code'].apply(categorize_department)
    overview_summary = final_summary_df.groupby('Description').agg( allocated_hours=('budget_for_hours', 'sum'), hours_worked=('total_adjusted_cost', 'sum') ).reset_index()
    overview_summary['department_code'] = overview_summary['Description'].map({ 'Resources': 1000, 'Material': 2001, 'Sub Contract': 3001, 'Optional': 4001, 'Others': 5000, 'something': 6000, 'Invalid': 0 })
    overview_summary_dict = overview_summary.to_dict(orient='records')
    cost_df = calculate_project_cost(id)
    #---------------------grpah data alone---------------------------------

    ranges = { "2000-3000": cost_df[(cost_df['department_code'] >= 2000) & (cost_df['department_code'] < 3000)], "3000-4000": cost_df[(cost_df['department_code'] >= 3000) & (cost_df['department_code'] < 4000)],
                "4000-5000": cost_df[(cost_df['department_code'] >= 4000) & (cost_df['department_code'] < 5000)],"500-600": cost_df[(cost_df['department_code'] >= 500) & (cost_df['department_code'] < 600)],}
    graphs_data = {
        key: {"labels": df['department_code'].tolist(),"allocated_hours": [round(value, 2) for value in df['allocated_hours']],"hours_worked": [round(value, 2) for value in df['hours_worked']]}
        for key, df in ranges.items()}

    merged_df = calculate_working_hours(id)

    resourse_graphs_data = {
            "labels": merged_df["department_code"].tolist(),
            "allocated_hours": merged_df["allocated_hours"].tolist(),
            "hours_worked": merged_df["hours_worked"].tolist(), }
    # Process data
    tables_data = {}
    for range_key, data in graphs_data.items():
        table = []
        total_allocated = 0
        total_worked = 0
        total_balance = 0

        # Calculate row-wise and totals
        for label, alloc, worked in zip(data["labels"], data["allocated_hours"], data["hours_worked"]):
            balance = alloc - worked
            table.append({"code": label, "allocated_hours": alloc, "hours_worked": worked, "balance": balance})
            total_allocated += alloc
            total_worked += worked
            total_balance += balance

        tables_data[range_key] = {
            "rows": table,
            "totals": {"allocated_hours": total_allocated, "hours_worked": total_worked, "balance": total_balance},
        }

    resource_range_key = "1000-1999"
    resource_table = []
    total_allocated = 0
    total_worked = 0
    total_balance = 0

    for label, alloc, worked in zip(
        resourse_graphs_data["labels"], resourse_graphs_data["allocated_hours"], resourse_graphs_data["hours_worked"] ):
        balance = alloc - worked
        resource_table.append({"code": label, "allocated_hours": alloc, "hours_worked": worked, "balance": balance})
        total_allocated += alloc
        total_worked += worked
        total_balance += balance

    tables_data[resource_range_key] = {
        "rows": resource_table,
        "totals": {"allocated_hours": total_allocated, "hours_worked": total_worked, "balance": total_balance},
    }

    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/projects/project_details_page.html', project_ids=project_ids, is_pm=is_pm, department_code=department_code,
                          insights=insights,po_data=po_data,pr_data=pr_data,user_access=user_access, user=user, project_id=id, project_details=project_details,
                          tables_data=tables_data,graphs_data=graphs_data,resourse_graphs_data=resourse_graphs_data,po_total_sum=po_total_sum)

def get_pr_data(project_id):
    import locale
    import pandas as pd
    # Connect to your database
    db = get_database()
    cursor = db.cursor()
    # Fetch PR data for the specified project_id
    cursor = db.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC',(project_id,))
    created_pr = cursor.fetchall()

    # Initialize an empty DataFrame to store the main data
    rows = []
    # Loop through each PR in created_pr
    for pr in created_pr:
        pr_id = pr[0]
        pr_no = pr[1]
        pr_date = pr[5]
        project_id = pr[2]
        supplier_name = pr[3]
        created_by = pr[6]
        status = pr[14]
        Code = pr[8] 
        Approved_by = pr[23] 


        # Fetch items for the current PR from pr_items table
        cursor.execute('SELECT id, item, quantity, uom, Unit_Price, total,excepted_date,status FROM pr_items WHERE pr_number = ?', (pr_no,))
        items = cursor.fetchall()

        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'ID': item[0], 'Description': item[1], 'QTY': item[2], 'UOM': item[3], 'Unit_Price': item[4], 'Total_Price': item[5], 'excepted_date': item[6],'status': item[7] })

        total_price_sum1 = round(sum([float(item[5]) for item in items]), 2)
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
        # Append the main row to the rows list
        rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum, 'Approved_by': Approved_by,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    grouped_df = pd.DataFrame(rows)
    return (grouped_df)

def get_po_data(project_id):
    import locale
    import pandas as pd
    

    # Connect to your database
    db = get_database()
    cursor = db.cursor()
    
    # Fetch all created PO records
    cursor.execute('SELECT * FROM created_po WHERE project_id = ? ORDER BY id DESC', (project_id,))
    created_po = cursor.fetchall()
    # print("........created_po................", created_po)
    
    # Initialize an empty list to store rows
    rows = []
    total_po_sum = 0  # Initialize total sum for all POs
    
    for pr in created_po:
        pr_id = pr[0]
        pr_no = pr[1]
        project_id = pr[2]
        supplier_name = pr[3]
        pr_date = pr[5]
        created_by = pr[6]
        Code = pr[8]
        status = pr[14]
        Approved_by = pr[23]
        PR_no_ref = pr[24]
        PO_Issued_by = pr[25]
        do_staus = pr[26]
        
        # Fetch items associated with the current PO number
        cursor.execute('SELECT item, quantity, uom, Unit_Price, total, excepted_date, status FROM po_items WHERE PO_number = ?', (pr_no,))
        items = cursor.fetchall()
        
        # Prepare aggregated values for sub-DataFrame
        sub_df_data = []
        for item in items:
            sub_df_data.append({
                'Description': item[0],
                'QTY': item[1],
                'UOM': item[2],
                'Unit_Price': item[3],
                'Total_Price': item[4],
                'excepted_date': item[5],
                'status': item[6]
            })
        
        # Calculate total sum for the current PO
        total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
        
        # Add to the overall total sum
        total_po_sum += total_price_sum1
        
        # Append the main row to the rows list
        rows.append({
            'ID': pr_id,
            'PO_Date': pr_date,
            'PO_no': pr_no,
            'Code': Code,
            'Project_ID': project_id,
            'Supplier': supplier_name,
            'Created_By': created_by,
            'Approved_by': Approved_by,
            'PR_no_ref': PR_no_ref,
            'PO_Issued_by': PO_Issued_by,
            'do_staus': do_staus,
            'Status': status,
            'PR_Total': total_price_sum,
            'Sub_DF': pd.DataFrame(sub_df_data)
        })
    
    # Create a grouped DataFrame
    grouped_df = pd.DataFrame(rows)
    
    # Format the overall total sum
    formatted_total_po_sum = locale.format_string("%0.2f", total_po_sum, grouping=True)
    
    # Return both the DataFrame and the total PO sum
    return grouped_df, formatted_total_po_sum

def get_claim_data(project_id):
    import locale
    import pandas as pd
    
    db = get_database()
    cursor = db.cursor()
    
    # Fetch all claimed items for the given project ID
    cursor.execute('SELECT * FROM claimed_items WHERE projectid = ? ORDER BY id DESC', (project_id,))
    claimed_items = cursor.fetchall()
    
    # Initialize an empty list to store rows
    rows = []
    total_claim_sum = 0  # Initialize total sum for all claims
    
    for claim in claimed_items:
        claim_id = claim[0]
        claim_by = claim[1]
        claim_date = claim[2]
        project_name = claim[4]
        category = claim[5]
        category_code = claim[6]
        sub_category = claim[7]
        sub_category_code = claim[8]
        vendor = claim[9]
        itemname = claim[10]
        currency = claim[11]
        comments = claim[12]
        rate = claim[13]
        invoice_number = claim[14]
        amount = claim[15]
        gst_percent = claim[16]
        gst_value = claim[17]
        gst = claim[18]
        total = claim[19]
        claim_no = claim[20]
        claim_type = claim[21]
        
        # Format GST and total as needed
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
        total_claim_sum += total
        
        # Prepare row data
        rows.append({
            'Claim_ID': claim_id,
            'Claim_By': claim_by,
            'Claim_Date': claim_date,
            'Project_Name': project_name,
            'Category': category,
            'Category_Code': category_code,
            'Sub_Category': sub_category,
            'Sub_Category_Code': sub_category_code,
            'Vendor': vendor,
            'Item_Name': itemname,
            'Currency': currency,
            'Comments': comments,
            'Rate': rate,
            'Invoice_Number': invoice_number,
            'Amount': amount,
            'GST_Percent': gst_percent,
            'GST_Value': gst_value,
            'GST': gst,
            'Total': total,
            'Claim_No': claim_no,
            'Claim_Type': claim_type
        })
    
    # Create a DataFrame for the claims
    claims_df = pd.DataFrame(rows)
    
    # Format the overall total claim sum
    formatted_total_claim_sum = locale.format_string("%0.2f", total_claim_sum, grouping=True)
    
    # Return the DataFrame and the total claim sum
    return claims_df, formatted_total_claim_sum

from calendar import monthrange
import calendar
@app.route('/hrs_view', methods=['GET', 'POST'])
@login_required
def hrs_view():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    from datetime import datetime, timedelta
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (department_code,))
    usernames = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT id FROM projects ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    if department_code == 1000:
        cursor.execute("SELECT code FROM cost_center ORDER BY CAST(code AS INTEGER) ASC")
        cost_center = [row[0] for row in cursor.fetchall()]
    else:
        cursor.execute("SELECT code FROM cost_center WHERE code >= ? ORDER BY CAST(code AS INTEGER) ASC", (department_code,))
        cost_center = [row[0] for row in cursor.fetchall()]
    user_access = get_employee_access_control(user['name'])
    return render_template("admin_templates/projects/hrs_view.html",department_code=department_code, cost_center=cost_center,
                           user=user,usernames=usernames, user_access=user_access ,project_ids=project_ids)

from calendar import monthrange
import calendar
@app.route('/prj_status', methods=['GET', 'POST'])
@login_required
def prj_status():

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code1 = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    if user_access and user_access.get("toggleAllstatusProjects") == 'On':
        cursor.execute("SELECT id, project_name, client, po_value, end_time FROM projects WHERE status != 'closed'  ORDER BY id DESC;" )
    elif user_access and user_access.get("toggleOnlyPMProjects") == 'On':
        cursor.execute("SELECT id, project_name, client, po_value, end_time FROM projects WHERE status != 'closed' AND pm = ? ORDER BY id DESC;", (user['name'],) )
    else:
        cursor.execute("SELECT id, project_name, client, po_value, end_time FROM projects WHERE status != 'closed' AND pm = ? ORDER BY id DESC;", ('sairam',) )

    projects = cursor.fetchall()

    project_data = []
    for project in projects:
        from datetime import datetime
        project_id, project_name, client, po_value, end_time = project
        if end_time:
            try:
                parsed_end_time = datetime.strptime(end_time, '%Y-%m-%d')
                formatted_end_time = parsed_end_time.strftime('%d/%m/%y')
            except ValueError:
                formatted_end_time = ""
        else:
            formatted_end_time = ""

        cursor.execute("""SELECT department_code, COALESCE(SUM(total), 0) FROM pmtable WHERE project_id = ? GROUP BY department_code """, (project_id,))

        # Initialize budgets
        material_budget = 0
        manpower_budget = 0

     
        # Fetch all results
        for row in cursor.fetchall():
            department_code, total = row
            department_code = int(department_code)  # Convert to integer for proper comparison

            if 1000 <= department_code <= 1020 or 10 <= department_code <= 100:
                manpower_budget += total
            else:
                material_budget += total


        # Print budget values
        print(f"Manpower Budget: {manpower_budget}")
        print(f"Material Budget: {material_budget}")

        # Fetch material actuals
        # Fetch material actuals with exchange rate and discount handling
        cursor.execute("""
            SELECT COALESCE(SUM(
                CASE 
                    WHEN COALESCE(exchange_rate, 0) = 0 THEN 0
                    ELSE ((total / exchange_rate) * (1 - COALESCE(discount, 0) / 100.0))
                END
            ), 0)
            FROM manual_entry
            WHERE project_id = ?
        """, (project_id,))
        material_actuals = cursor.fetchone()[0]


        # Fetch manpower actuals
        cursor.execute("""SELECT departmentID, COALESCE(SUM(total_cost), 0) AS total_department_cost FROM workingHours WHERE projectID = ? GROUP BY departmentID """, (project_id,))
        manpower_actuals = sum(row[1] for row in cursor.fetchall())

        # Print actuals
        print(f"Material Actuals: {material_actuals}")
        print(f"Manpower Actuals: {manpower_actuals}")

        # Calculate balances
        material_balance = material_budget - material_actuals
        manpower_balance = manpower_budget - manpower_actuals

        # Print balances
        print(f"Material Balance: {material_balance}")
        print(f"Manpower Balance: {manpower_balance}")

        # Fetch total invoice amount
        cursor.execute("SELECT SUM(total) FROM created_invoice WHERE prj_id = ?", (project_id,))
        Inv_total = cursor.fetchone()[0] or 0

        # Calculate final budget and actuals sum
        final_budget_sum = material_budget + manpower_budget
        total_actuals = material_actuals + manpower_actuals

        # Add data to project_data list
        project_data.append({
            'id': project_id,
            'project_name': project_name,
            'client': client,
            'po_value': po_value,
            'end_time': formatted_end_time,
            'material_budget': round(material_budget, 2),
            'manpower_budget': round(manpower_budget, 2),
            'material_actuals': round(material_actuals, 2),
            'manpower_actuals': round(manpower_actuals, 2),
            'material_balance': round(material_balance, 2),
            'manpower_balance': round(manpower_balance, 2),
            'Inv_total': round(Inv_total, 2)
        })
    print(".....project_data........",project_data)

    return render_template('admin_templates/projects/prj_status.html', 
                           user_access=user_access, user=user, department_code=department_code1, project_list=project_data)

from datetime import datetime
import calendar

@app.route('/get_working_data', methods=['POST'])
def get_working_data():
    db = get_database()
    cursor = db.cursor()
    data = request.json  
    project_id = None if data.get('project_id') == "All" else data.get('project_id')
    employee_id = None if data.get('employee_id') == "All" else data.get('employee_id')
    section_code = None if data.get('section_code') == "All" else data.get('section_code')
    department_code = None if data.get('department_code') == "All" else data.get('department_code')
    start_date = None if data.get('start_date') == "" else data.get('start_date')
    end_date = None if data.get('end_date') == "" else data.get('end_date')

    # Construct SQL query with dynamic filters
    query = """SELECT employeeID, projectID, workingDate, total_cost, departmentID FROM workingHours WHERE 1=1"""
    params = []

    if project_id:
        query += " AND projectID = ?"
        params.append(project_id)
    if employee_id:
        query += " AND employeeID = ?"
        params.append(employee_id)
    if section_code:
        query += " AND section_code = ?"
        params.append(section_code)
    if department_code:
        query += " AND departmentID = ?"
        params.append(department_code)
    if start_date:
        query += " AND formatted_date >= ?"
        params.append(start_date)
    if end_date:
        query += " AND formatted_date <= ?"
        params.append(end_date)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    # Organize data by employee or project, based on employee_id
    project_hours = {}  
    for row in rows:
        emp_id, project_id, work_date, hours_worked, dept_id = row

        # If employee_id is not "All", use project_id instead of employee_id
        if employee_id and employee_id != "All":
            emp_id = project_id  # Treat projectID as employeeID when employee_id is specified

        # Ensure hours_worked is a float (default to 0.0 if None)
        hours_worked = float(hours_worked or 0)

        if emp_id not in project_hours:
            project_hours[emp_id] = {
                'total_hours': 0.0,
                'date_hours': {},
                'departmentID': dept_id
            }

        if work_date not in project_hours[emp_id]['date_hours']:
            project_hours[emp_id]['date_hours'][work_date] = hours_worked
        else:
            project_hours[emp_id]['date_hours'][work_date] += hours_worked

        project_hours[emp_id]['total_hours'] += hours_worked



    # Retrieve leave data
    leave_dates_dict = {}
    cursor.execute('SELECT employeeID, leave_date FROM leaves')
    leave_rows = cursor.fetchall()
    
    for row in leave_rows:
        emp_id, leave_date = row
        from datetime import datetime
        formatted_leave_date = datetime.strptime(leave_date, '%Y-%m-%d').strftime('%d %m %Y')
        if emp_id not in leave_dates_dict:
            leave_dates_dict[emp_id] = []
        leave_dates_dict[emp_id].append(formatted_leave_date)

    # Add leave data to employees
    data_list = []
    for emp_id, details in project_hours.items():
        data_list.append({
            'employeeID': emp_id,
            'departmentID': details['departmentID'],
            'date_hours': details['date_hours'],
            'total_hours': details['total_hours'],
            'leaves': leave_dates_dict.get(emp_id, [])
        })

    total_hours_sum = sum(emp['total_hours'] for emp in data_list)
    return jsonify({
        "message": "Data received successfully",
        "status": "success",
        "total_hours_sum": total_hours_sum,
        "data": data_list
    })

from datetime import datetime, timedelta
from werkzeug.exceptions import BadRequest
from datetime import datetime

def get_allowed_departments(depart, username):
    # Dictionary defining which departments can manage others
    department_hierarchy = {

        10: [10,11,12,13,14,15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        11: [11,12,13,14,15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        12: [12,13,14,15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        13: [13,14,15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        14: [14,15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        15: [15,16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        16: [16,17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        17: [17,18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        18: [18,19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        19: [19, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        1000: [0,11,12,13,14,15,16,17,18,19,1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        1001: [1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        1002: [1002, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        1003: [1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015],
        1004: [1004],
        1005: [1005, 1010, 1011, 1012, 1013, 1014, 1015],
        1006: [1006],
        1007: [1007, 1009],
        1008: [1008],
        1009: [1009],
        1010: [1010],
        1011: [1011],
        1012: [1012],
        1013: [1013],
        1014: [1014],
        1015: [1015]
    }

    # For specific departments, return only the current user's username
    if depart in [1004, 1006, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015]:
        return [username]  # Only include the current user
    else:
        return department_hierarchy.get(depart, [depart])

@app.route('/deleteuser_claim/<int:claimid>', methods=["GET", "POST"])
@login_required
def deleteuser_claim(claimid):   
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        cursor = db.execute("SELECT claim_id FROM claims WHERE id = ?", (claimid,))
        claim_no = cursor.fetchone()[0]
        db.execute('DELETE FROM claimed_items WHERE claim_no = ?', [claim_no])
        db.execute('DELETE FROM claims WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('prof_claim'))
    return render_template('prof_claim.html', user=user)

@app.route('/claiminfo', methods=['GET', 'POST'])
@login_required
def claiminfo():
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    cursor = db.cursor()
    project_id = request.args.get('project_id', type=int)
    i_am_pm = pm_or_not_for_project(project_id)
    # print(".......i_am_pm..........",i_am_pm)

     # Step 1: Get distinct claim_no for the given project ID
    cursor.execute("SELECT DISTINCT claim_no FROM claimed_items WHERE projectid = ?", (project_id,))
    claim_nos = [row[0] for row in cursor.fetchall()]

    # Step 2: Calculate totals for each claim_no and project_id, and fetch details from claims table
    results = []
    for claim_no in claim_nos:
        # Calculate total from claimed_items for the claim_no and project ID
        cursor.execute(""" SELECT SUM(total) AS claim_total FROM claimed_items WHERE claim_no = ? AND projectid = ? """, (claim_no, project_id))
        calculated_total = cursor.fetchone()[0] or 0  # Handle cases where no total is found


        # print("......total........",calculated_total)
        
        # Fetch details from claims table for the claim_no
        if i_am_pm == user['name'] or department_code == 1000:
            cursor.execute(""" SELECT * FROM claims WHERE claim_id = ? """, (claim_no,))
            claim_details = cursor.fetchone()
        else:
            cursor.execute(""" SELECT * FROM claims WHERE claim_id = ? AND claim_by = ? """, (claim_no,user['name']))
            claim_details = cursor.fetchone()
        
        # Combine claim details with the calculated total
        if claim_details:
            # Convert claim_details to a dictionary for easier manipulation
            claim_columns = [description[0] for description in cursor.description]
            claim_dict = dict(zip(claim_columns, claim_details))
            
            # Modify the claim_Total field with the calculated total
            claim_dict['claim_Total'] = calculated_total
            
            # Append modified data to results
            results.append(claim_dict)

    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 
    # print(".............project_details........\n",project_details)

    query = """ SELECT SUM(CAST(total AS REAL))  FROM claimed_items  WHERE projectid = ? """
    cursor.execute(query, (project_id,))

    # Fetch the result and store it in a variable
    total_sum = cursor.fetchone()[0]

    # Check if the result is None (no rows match the project_id)
    if total_sum is None:
        total_sum = 0.0

    # Print the total sum
    total_sum = locale.format_string("%0.2f", total_sum, grouping=True)

    # print(f"The total sum for project_id {project_id} is: {total_sum}")

    chart_data = {}
    for result in results:
        category = result['claim_type']
        total = result['claim_Total']
        if category in chart_data:
            chart_data[category] += total
        else:
            chart_data[category] = total

    # print("...........chart_data...................",chart_data)

    return render_template('admin_templates/projects/project_claim.html', user_access=user_access, user=user, 
                           department_code=department_code, project_id=project_id, chart_data=chart_data,
                            total_sum=total_sum,project_details=project_details,results=results)

@app.route('/fetch_claim_items', methods=['GET'])
def fetch_claim_items():
    db = get_database()
    cursor = db.cursor()
    claim_id = request.args.get('claim_id')
    project_id = request.args.get('project_id')

    if not claim_id or not project_id:
        return jsonify({"error": "Missing claim_id or project_id"}), 400

    # Fetch items for the claim
    query_items = """ SELECT * FROM claimed_items  WHERE claim_no = ? AND projectid = ? """
    cursor.execute(query_items, (claim_id, project_id))
    items = cursor.fetchall()

    # Fetch total sum of items
    query_sum = """ SELECT SUM(total) AS total_sum  FROM claimed_items  WHERE claim_no = ? AND projectid = ? """
    cursor.execute(query_sum, (claim_id, project_id))
    total_sum = cursor.fetchone()['total_sum']

    # Fetch claim details
    query_claim = """ SELECT * FROM claims  WHERE claim_id = ? """
    cursor.execute(query_claim, (claim_id,))
    claim_details = cursor.fetchone()

    return jsonify({ "items": [dict(row) for row in items], "total_sum": total_sum, "claim_details": dict(claim_details)})

def pm_or_not_for_project(projectid):                                                                                                                                                                                                                             
    # print("we are in get pm status function .......................her eis  pm name.......",pm_name)
    db = get_database()
    result = db.execute('SELECT pm FROM projects WHERE id = ?', [projectid]).fetchone()
    # print("after selecting from the table status .....................................",result)
    if result is None:
        return 0
    if result:
        pm = result['pm']
        return pm
    else:
        return 0

@app.route('/deletenonpo/<int:claimid>', methods=["GET", "POST"])
@login_required
def deletenonpo(claimid):   
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM temp_claims WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('prof_claim'))
    return render_template('prof_claim.html', user=user)

@app.route('/enquiry_name')
@login_required
def enquiry_name():
    enquiry_number = request.args.get('enquiry_number')
    
    if enquiry_number:
        db = get_database()
        cursor = db.cursor()
        cursor.execute('SELECT Name FROM enquiries WHERE EnquiryNumber = ?', (enquiry_number,))
        result = cursor.fetchone()
        
        
        if result:
            return result[0]  # Return the name
        else:
            return "Name not found"  # Handle case where name is not found
    else:
        return "Invalid enquiry number"

@app.route('/purchase_edit', defaults={'id': None}, methods=["POST", "GET"])
@app.route('/purchase_edit/<int:id>', methods=["POST", "GET"])
@login_required
def purchase_edit(id):

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    # Accessing the query parameter 'p'
    p = request.args.get('p', default=None, type=int)

    if p == 2:

        if request.method == 'POST':

            PO_Print = request.form.get ('PO_Print')
            action = request.form.get('action')

            if action == 'update_header':
                project_id = request.form.get('project_id', type=int)
                Supplier_Name = request.form.get('Supplier_Name')
                # Query to fetch the details from vendors_details table based on the Supplier_Name
                query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
                cursor.execute(query, (Supplier_Name,))
                result = cursor.fetchone()

                if result:
                    Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
                    Supplier_address3 = f"{country}, {city} - {postcode}"

                Attn = request.form.get('Attn')
                leat_time = request.form.get('leat_time')
                Contact = request.form.get('Contact')
                phone_number = request.form.get('number')
                PO_Date = request.form.get('PO_Date') 
                Old_PO_no = request.form.get('Old_PO_no')
                New_PO_no = request.form.get('New_PO_no')

                parts = Old_PO_no.split('-')
                if len(parts) == 3:
                    project_id1 = parts[0]
                    serial_number1 = parts[2]
                cursor.execute("SELECT id FROM created_po where PO_no = ?", (Old_PO_no,))
                header_id = cursor.fetchone()[0]  
                Quote_Ref = request.form.get('Quote_Ref')


                comments = request.form.get('comments')
                Delivery = request.form.get('Delivery')
                Address_Line1 = request.form.get('Address_Line1')
                Address_Line2 = request.form.get('Address_Line2')
                Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
                Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
                # Update the created_pr table with updated header details
                db = get_database()
                cursor = db.cursor()
                cursor.execute(''' UPDATE created_po SET PO_no = ?, Supplier_Name = ?, Attn = ?,  phone_number = ?, PO_Date = ?, Quote_Ref = ?,  Delivery = ?, Address_Line1 = ?,  Address_Line2 = ?,  Payment_Terms = ?, 
                        Currency = ?, comments = ?,  Supplier_address1 = ?,  Supplier_address2 = ?,  Supplier_address3 = ?,  Company_name = ?,  leat_time = ?, created_by=?, status = ? WHERE id = ? ''', 
                        ( New_PO_no, Supplier_Name, Attn, phone_number, PO_Date, Quote_Ref, Delivery,  Address_Line1, Address_Line2,  Payment_Terms, 
                        Currency, comments,  Supplier_address1, Supplier_address2, Supplier_address3,  Company_name,  leat_time, Contact, 'Reissued', header_id ))
                
                cursor.execute(''' UPDATE po_items SET PO_number = ? WHERE PO_number = ? ''', (New_PO_no, Old_PO_no))
                db.commit()
                flash('PO Header Updated successfully!', 'po_emp_head_update')
                
                cursor.execute("SELECT * FROM created_po where PO_no = ?", (New_PO_no,))
                header_details = cursor.fetchone() 
                if header_details:
                    for key in header_details.keys():
                        print(f"{key}: {header_details[key]}")
                else:
                    print("No records found")
                cursor.execute('SELECT display_name FROM vendors_details')
                Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
                cursor.execute('SELECT username FROM admin_user')
                usernames = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (New_PO_no,))
                pr_items = cursor.fetchall()
                db.commit()
                p = 2
                show = 'po'
                user_access = get_employee_access_control(user['name'])


                return render_template('admin_templates/projects/purchase_edit.html',project_id=project_id1,pr_items=pr_items,Supplier_Names=Supplier_Names,usernames=usernames, 
                                 user_access=user_access, show = show,  p = p, New_PO_no=New_PO_no,user=user,department_code=department_code,header_details=header_details, is_pm=is_pm)

            if action == 'update_po':

                project_id = request.form.get('project_id')
                PO_number = request.form.get('PO_no')
                New_PO_no  = request.form.get('New_PO_no')
                gst_checkbox = request.form.get('gstCheckbox')
                part_nos = request.form.getlist('part_no[]')
                descriptions = request.form.getlist('description[]')
                uoms = request.form.getlist('uom[]')
                quantities = request.form.getlist('quantity[]')
                unit_prices = request.form.getlist('unit_price[]')
                items = []
                cursor.execute("DELETE FROM po_items WHERE PO_number = ?", (PO_number,))

                for part_no, description, uom, quantity, unit_price in zip(part_nos, descriptions, uoms, quantities, unit_prices):
                    total = float(quantity) * float(unit_price)
                    rounded_total = round(total, 2) 
                    item = { 'project_id': project_id,'PO_number': New_PO_no, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 'unit_price': float(unit_price), 'total': rounded_total }
                    if gst_checkbox:
                        item['gst'] = 1
                    else:
                        item['gst'] = 0
                    items.append(item)

                if items:

                    for item in items:
                        cursor.execute("""INSERT INTO po_items (project_id, PO_number, Part_No, item, quantity, uom, Unit_Price, GST, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                                    (item['project_id'], item['PO_number'], item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'], item['gst'], item['total']))

                        total_sum = float(item['total'].replace(',', ''))
                        cost = item['quantity'] * item['Unit_Price']

                        parts = New_PO_no.split('-')
                        print(".....parts.........",parts)
                        if len(parts) == 3:
                            Expenses = parts[1]
                        print(".....parts.........",parts)
                        cursor.execute("INSERT INTO manual_entry (project_id, username, department_code, cost, gst_value, total, cost_center_id) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                    (project_id, user['name'], Expenses, cost , item['GST'], total_sum,New_PO_no ))
                    db.commit()  
                    # Update the status of the PR
                    # status = 'Approved' if department_code <= 1001 else 'Created'
                    # cursor.execute("UPDATE created_po SET status = ? WHERE PO_no = ?", (status, PO_number))
                    from datetime import datetime
                    current_date = datetime.now()
                    formatted_date = current_date.strftime("%d-%m-%y")
                    cursor.execute('''UPDATE created_po SET PO_no = ?, PO_Date = ?  WHERE PO_no = ?''',  (New_PO_no, formatted_date, PO_number))
                    cursor.execute('''UPDATE created_po SET status = ? WHERE PO_no = ?''',  ('Reissued',New_PO_no))
                    db.commit()
                
                else:
                    cursor.execute("DELETE FROM created_po WHERE PO_no = ? AND project_id = ?", (PO_number, project_id))
                    db.commit()

                # Fetch all created PR records
                cursor = db.execute('SELECT * FROM created_pr ORDER BY id DESC')
                created_pr = cursor.fetchall()

                cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
                created_po = cursor.fetchall()
                rows1 = []
                # Loop through each PR in created_po
                for pr in created_po:
                    pr_id = pr[0]
                    pr_no = pr[1]
                    pr_date = pr[5]
                    project_id = pr[2]
                    supplier_name = pr[3]
                    created_by = pr[6]
                    status = pr[14]
                    Code = pr[8]
                    Approved_by = pr[23] 

                    cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM po_items WHERE PO_number = ?', (pr_no,))
                    items = cursor.fetchall()
                    # Prepare aggregated values as a list of dictionaries (for sub_df)
                    sub_df_data = []
                    for item in items:
                        sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
                    total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
                    total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
                    # Append the main row to the rows list
                    rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by, 'Approved_by': Approved_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })
                    
                # Convert rows to a pandas DataFrame
                grouped_df_po = pd.DataFrame(rows1)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr")
                PR_count = cursor.fetchone()[0]
                rows = []
                # Loop through each PR in created_pr
                for pr in created_pr:
                    pr_id = pr[0]
                    pr_no = pr[1]
                    pr_date = pr[5]
                    project_id = pr[2]
                    supplier_name = pr[3]
                    created_by = pr[6]
                    status = pr[14]
                    Code = pr[8]
                    Approved_by = pr[23]

                    # Fetch items for the current PR from pr_items table
                    cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM pr_items WHERE pr_number = ?', (pr_no,))
                    items = cursor.fetchall()
                    # Prepare aggregated values as a list of dictionaries (for sub_df)
                    sub_df_data = []
                    for item in items:
                        sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
                    total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
                    total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
                    # Append the main row to the rows list
                    rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name,  'Approved_by': Approved_by,'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })

                # Convert rows to a pandas DataFrame
                grouped_df_pr = pd.DataFrame(rows)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr ")
                PR_count = cursor.fetchone()[0]
                user_access = get_employee_access_control(user['name'])

                db.commit()
                db.close()
                show = 'po'
                p = 2
                search_values = [0, 0, 0]
                search_values1 = [0, 0, 0]
                return render_template('admin_templates/projects/Emp_purchase.html', PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr, user=user, p = p,
                                   user_access=user_access,search_values=search_values, search_values1=search_values1, show = show, department_code=department_code, is_pm=is_pm)

            if PO_Print:
                show = 'po'
                cursor.execute('SELECT PO_no FROM created_po WHERE id = ?', (PO_Print,))
                PO_number = cursor.fetchone()
                cursor.execute('SELECT * FROM created_po WHERE id = ?', (PO_Print,))
                po_details = cursor.fetchone()

                if po_details:
                    column_names = [description[0] for description in cursor.description]
                    po_dict = dict(zip(column_names, po_details))

                else:
                    print("No PO found with the given ID.")

                # Check if a result was found before trying to access it
                if PO_number is not None:
                    PO_number = PO_number[0]
                    cursor.execute(''' SELECT Part_No, item, quantity, uom, Unit_Price, total, GST FROM po_items WHERE PO_number = ? ''', (PO_number,))
                    po_items = cursor.fetchall()

                    # Store the fetched details in a dictionary
                    total_sum = 0 
                    
                    data_dict = []
                    for item in po_items:
                        # print(".......'total': item[5]......................",item[5])
                        item_dict = { 'Part_No': item[0], 'item': item[1], 'quantity': item[2], 'uom': item[3], 'Unit_Price': item[4], 'total': item[5], 'GST': item[6] }
                        data_dict.append(item_dict)
                        total_sum += float(item[5].replace(',', '')) 

                    total_sum = "{:,.2f}".format(total_sum)


                    pdf_filename = claim_to_po_pdf(data_dict, total_sum, po_details)
                    if pdf_filename:
                        db.commit()
                        # Serve the PDF directly
                        return po_pdf_and_refresh(pdf_filename)
                    
                else:
                    print("No PO number found for the given ID:", PO_Print)

        cursor.execute('SELECT display_name FROM vendors_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

        cursor.execute('SELECT username FROM admin_user')
        usernames = sorted([row[0] for row in cursor.fetchall()])

        cursor.execute("SELECT * FROM created_po where id = ?", (id,))
        header_details = cursor.fetchone() 
        cursor.execute("SELECT PO_no FROM created_po WHERE id = ?", (id,))
        result = cursor.fetchone()

        if result is not None:
            ponumber = result[0]
        else:
            # Handle the case where no rows were returned
            ponumber = None

        # Fetch pr_items associated with pr_number
        cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (ponumber,))
        pr_items = cursor.fetchall()
        parts = ponumber.split('-')
        if len(parts) == 3:
            project_id = parts[0]

        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d-%m-%y")
        ponumber = ponumber.strip()
        # pattern = re.compile(r"(\d{4}-\d{4}-\d{4}|\d{4}-\d{3}-\d{4})(\((\d+)\))?$")
        pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
        match = pattern.match(ponumber)
        if match:
            base_pr_number = match.group(1)
            suffix = match.group(3)
            if suffix:
                new_suffix = int(suffix) + 1
            else:
                new_suffix = 1
            New_PO_no = f"{base_pr_number}({new_suffix})"
        
        else:
            # If the PR number format is incorrect
            New_PO_no = "Invalid PR number format"

        show = 'po'
        user_access = get_employee_access_control(user['name'])
        return render_template('admin_templates/projects/purchase_edit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                          user_access=user_access,show = show, New_PO_no=New_PO_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

    if p == 1:

        if request.method == 'POST':

            action = request.form.get('action')

            if action == 'update_header':
                project_id = request.form.get('project_id', type=int)
                Supplier_Name = request.form.get('Supplier_Name')
                # Query to fetch the details from vendors_details table based on the Supplier_Name
                query = ''' SELECT  billing_address1,  billing_address2,  city,  postcode, country, company_name  FROM vendors_details  WHERE  display_name = ?'''
                cursor.execute(query, (Supplier_Name,))
                result = cursor.fetchone()

                if result:
                    Supplier_address1, Supplier_address2, city, postcode, country, Company_name = result
                    Supplier_address3 = f"{country}, {city} - {postcode}"

                Attn = request.form.get('Attn')
                leat_time = request.form.get('leat_time')
                Contact = request.form.get('Contact')
                phone_number = request.form.get('number')
                PR_Date = request.form.get('PR_Date') 
                Old_PR_no = request.form.get('Old_PR_no')
                New_PR_no = request.form.get('New_PR_no')
                parts = Old_PR_no.split('-')
                if len(parts) == 3:
                    project_id1 = parts[0]
                    serial_number1 = parts[2]
                cursor.execute("SELECT id FROM created_pr where PR_no = ?", (Old_PR_no,))
                header_id = cursor.fetchone()[0]  
                Quote_Ref = request.form.get('Quote_Ref')


                comments = request.form.get('comments')
                Delivery = request.form.get('Delivery')
                Address_Line1 = request.form.get('Address_Line1')
                Address_Line2 = request.form.get('Address_Line2')
                Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
                Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
                db = get_database()
                cursor = db.cursor()
                # Update the created_pr table with updated header details
                cursor.execute(''' UPDATE created_pr SET PR_no = ?, Supplier_Name = ?, Attn = ?,  phone_number = ?, PR_Date = ?, Quote_Ref = ?,  Delivery = ?, Address_Line1 = ?,  Address_Line2 = ?,  Payment_Terms = ?, 
                        Currency = ?, comments = ?,  Supplier_address1 = ?,  Supplier_address2 = ?,  Supplier_address3 = ?,  Company_name = ?,  leat_time = ?, created_by=? WHERE id = ? ''', 
                        ( New_PR_no, Supplier_Name, Attn, phone_number, PR_Date, Quote_Ref, Delivery,  Address_Line1, Address_Line2,  Payment_Terms, 
                        Currency, comments,  Supplier_address1, Supplier_address2, Supplier_address3,  Company_name,  leat_time, Contact, header_id ))
                
                cursor.execute(''' UPDATE pr_items SET pr_number = ? WHERE pr_number = ? ''', (New_PR_no, Old_PR_no))
                db.commit()
                flash('Header updated successfully!', 'edit_emp_pr')
                
                cursor.execute("SELECT * FROM created_pr where PR_no = ?", (New_PR_no,))
                header_details = cursor.fetchone() 
                cursor.execute('SELECT display_name FROM vendors_details')
                Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])
                cursor.execute('SELECT username FROM admin_user')
                usernames = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (New_PR_no,))
                pr_items = cursor.fetchall()
                db.commit()
                show = 'pr'
                p =1
                user_access = get_employee_access_control(user['name'])

                return render_template('admin_templates/projects/purchase_edit.html',project_id=project_id1,pr_items=pr_items,Supplier_Names=Supplier_Names,usernames=usernames, 
                                   user_access=user_access,show = show, p = p, New_PR_no=New_PR_no,user=user,department_code=department_code,header_details=header_details, is_pm=is_pm)

            if action == 'update_pr':

                project_id = request.form.get('project_id')
                pr_number = request.form.get('PR_no')
                New_PR_no  = request.form.get('New_PR_no')
                gst_checkbox = request.form.get('gstCheckbox')
                part_nos = request.form.getlist('part_no[]')
                descriptions = request.form.getlist('description[]')
                uoms = request.form.getlist('uom[]')
                quantities = request.form.getlist('quantity[]')
                unit_prices = request.form.getlist('unit_price[]')
                items = []
                cursor.execute("DELETE FROM pr_items WHERE pr_number = ?", (pr_number,))

                for part_no, description, uom, quantity, unit_price in zip(part_nos, descriptions, uoms, quantities, unit_prices):
                    total = float(quantity) * float(unit_price)
                    rounded_total = round(total, 2) 
                    item = { 'project_id': project_id,'pr_number': New_PR_no, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 'unit_price': float(unit_price), 'total': rounded_total }
                    if gst_checkbox:
                        item['gst'] = 1
                    else:
                        item['gst'] = 0
                    items.append(item)

                if items:

                    for item in items:
                        cursor.execute("""INSERT INTO pr_items (project_id, pr_number, Part_No, item, quantity, uom, Unit_Price, GST, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                                    (item['project_id'], item['pr_number'], item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'], item['gst'], item['total']))
                    db.commit()  
                    # Update the status of the PR
                    # status = 'Approved' if department_code <= 1001 else 'Created'
                    # cursor.execute("UPDATE created_pr SET status = ? WHERE PR_no = ?", (status, pr_number))
                    from datetime import datetime
                    current_date = datetime.now()
                    formatted_date = current_date.strftime("%d-%m-%y")
                    cursor.execute('''UPDATE created_pr SET PR_no = ?, PR_Date = ?  WHERE PR_no = ?''',  (New_PR_no, formatted_date, pr_number))
                    db.commit()
                
                else:
                    cursor.execute("DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?", (pr_number, project_id))
                    db.commit()


                # Fetch all created PR records
                cursor = db.execute('SELECT * FROM created_pr ORDER BY id DESC')
                created_pr = cursor.fetchall()

                cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
                created_po = cursor.fetchall()
                rows1 = []
                # Loop through each PR in created_po
                for pr in created_po:
                    pr_id = pr[0]
                    pr_no = pr[1]
                    pr_date = pr[5]
                    project_id = pr[2]
                    supplier_name = pr[3]
                    created_by = pr[6]
                    status = pr[14]
                    Code = pr[8]
                    Approved_by = pr[23]

                    cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM po_items WHERE PO_number = ?', (pr_no,))
                    items = cursor.fetchall()
                    # Prepare aggregated values as a list of dictionaries (for sub_df)
                    sub_df_data = []
                    for item in items:
                        sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
                    total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
                    total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
                    # Append the main row to the rows list
                    rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Approved_by': Approved_by, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })
                    
                # Convert rows to a pandas DataFrame
                grouped_df_po = pd.DataFrame(rows1)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr")
                PR_count = cursor.fetchone()[0]
                rows = []
                # Loop through each PR in created_pr
                for pr in created_pr:
                    pr_id = pr[0]
                    pr_no = pr[1]
                    pr_date = pr[5]
                    project_id = pr[2]
                    supplier_name = pr[3]
                    created_by = pr[6]
                    status = pr[14]
                    Code = pr[8]
                    Approved_by = pr[23]

                    # Fetch items for the current PR from pr_items table
                    cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM pr_items WHERE pr_number = ?', (pr_no,))
                    items = cursor.fetchall()
                    # Prepare aggregated values as a list of dictionaries (for sub_df)
                    sub_df_data = []
                    for item in items:
                        sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
                    total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  
                    total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
                    # Append the main row to the rows list
                    rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by, 'Approved_by': Approved_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })

                # Convert rows to a pandas DataFrame
                grouped_df_pr = pd.DataFrame(rows)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr ")
                PR_count = cursor.fetchone()[0]
                user_access = get_employee_access_control(user['name'])

                db.commit()
                db.close()
                show = 'pr'
                p =1
                search_values = [0, 0, 0]
                search_values1 = [0, 0, 0]

                return render_template('admin_templates/projects/Emp_purchase.html', PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr, user=user, p = p,
                                   user_access=user_access,search_values=search_values, search_values1=search_values1, show = show, department_code=department_code, is_pm=is_pm)

        cursor.execute('SELECT display_name FROM vendors_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall() if row[0] is not None])

        cursor.execute('SELECT username FROM admin_user')
        usernames = sorted([row[0] for row in cursor.fetchall()])

        cursor.execute("SELECT * FROM created_pr where id = ?", (id,))
        header_details = cursor.fetchone() 
        cursor.execute("SELECT PR_no FROM created_pr where id = ?", (id,))
        prnumber = cursor.fetchone()[0]  
        # Fetch pr_items associated with pr_number
        cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (prnumber,))
        pr_items = cursor.fetchall()
        parts = prnumber.split('-')

        if len(parts) == 3:
            project_id = parts[0]

        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d-%m-%y")
        prnumber = prnumber.strip()
        # pattern = re.compile(r"(\d{4}-\d{4}-\d{4}|\d{4}-\d{3}-\d{4})(\((\d+)\))?$")
        pattern = re.compile(r"(\d+-\d{3,4}-\d{4})(\((\d+)\))?$")
        match = pattern.match(prnumber)
        print("........match.......",match)

        if match:
            base_pr_number = match.group(1)
            suffix = match.group(3)
            if suffix:
                new_suffix = int(suffix) + 1
            else:
                new_suffix = 1
            New_PR_no = f"{base_pr_number}({new_suffix})"
        else:
            # If the PR number format is incorrect
            New_PR_no = "Invalid PR number format"
            
        show = 'pr'
        p =1
        user_access = get_employee_access_control(user['name'])

        return render_template('admin_templates/projects/purchase_edit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                           user_access=user_access,show =show, New_PR_no=New_PR_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

@app.route('/get_hourly_rate', methods=['POST'])
def get_hourly_rate():
    code = request.json.get('code')
    if not code:
        return jsonify({'error': 'Code is required'}), 400
    db = get_database()  
    cursor = db.cursor()
    cursor.execute("SELECT hourly_rate FROM cost_center WHERE code = ?", (code,))
    result = cursor.fetchone()
    if result:
        return jsonify({'hourly_rate': result[0]})
    else:
        return jsonify({'hourly_rate': 1})  

@app.route('/delete_project_request/<int:project_id>', methods=['DELETE'])
def delete_project_request(project_id):
    db = get_database()  
    cursor = db.cursor()
    try:
        # Check if the project exists before deleting
        cursor.execute('SELECT * FROM projects_request WHERE id = ?', (project_id,))
        project = cursor.fetchone()
        if project is None:
            return jsonify({'success': False, 'message': 'Project not found'}), 404
        # Delete the project and related data from the database
        db.execute('DELETE FROM projects_request WHERE id = ?', (project_id,))
        db.execute('DELETE FROM request_pmtable WHERE project_id = ?', (project_id,))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

def calculate_budget(resources1):
    # print("........resources1..............",resources1)
    db = get_database()  
    cursor = db.cursor()
    total_cost = 0.0  # Initialize total cost variable
    for department_code, hours in resources1.items():
        department_code = int(department_code)
        
        # Ensure hours is treated as a float
        try:
            hours = float(hours)  # Convert hours to float if it is a valid numeric value
        except ValueError:
            hours = 0.0  # If it's not a valid number, default to 0.0
        # Fetch hourly rate for department codes less than 2000 from the cost_center table
        if (1000 <= department_code < 2000) or (10 <= department_code <= 100):
            cursor.execute('SELECT hourly_rate FROM cost_center WHERE code = ?', (department_code,))
            row = cursor.fetchone()
            hourly_rate = row[0] if row else 0.0
            # Calculate the cost for this department
            department_cost = hours * hourly_rate
        else:
            department_cost = hours  # For department codes >= 2000, no hourly rate is applied
        # Add the department cost to the total
        # print("........department_code..............",department_code,".....",department_cost)
        total_cost += department_cost
    # Round the total cost to two decimal places
    total_cost = round(total_cost, 2)
    return total_cost  # Return the total cost of all departments

def Project_request_approval_Notification(mail_to_list, project_id, approved_by):
    # print("...........project_id.......",project_id)
    # Establish connection with SMTP server
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    # Set subject and email body
    subject = f"New Project Request - {project_id}"
    body = (
        "test mail please igore...\n\n"
        f"Dear Sir/Madam,\n\n"
        f"We are pleased to inform you that a new project creation request has been approved.\n\n"
        f"Project Details:\n"
        f"Project ID: {project_id}\n"
        f"Approved By: {approved_by}\n\n"
        f"The project is now ready for further action.\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    server = None  # Initialize server to ensure it's defined
    try:
        # Send email to each recipient in the mail_to_list
        for mail_to in mail_to_list:
            # Construct the email for each recipient
            message = MIMEMultipart()
            message['From'] = "cestimesheet67@gmail.com"
            message['To'] = mail_to
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            # Send the email
            s.sendmail("cestimesheet67@gmail.com", mail_to, message.as_string())
            print(f'Project creation request email sent to {mail_to} successfully.')

    except Exception as e:
        print(f"Error sending email: {e}")
    finally:
        if server:
            server.quit()

def Project_created_by_admin_Notification(mail_to_list,pm, team_members, project_id):
    # Establish connection with SMTP server
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    # Set subject and email body
    subject = f"New Project - {project_id}"

    # Create team member string
    team_members_str = ', '.join(team_members)

    # Email body
    body = (
        # f"TEST MAIL PLEASE IGNORE\n\n"
        f"Dear Sir/Madam,\n\n"
        f"A new project has been created with the following details:\n\n"
        f"Project ID: {project_id}\n"
        f"Project Manager (PM): {pm}\n"
        f"Team Members: {team_members_str}\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )


    server = None  # Initialize server to ensure it's defined
    try:
        # Send email to each recipient in the mail_to_list
        for mail_to in mail_to_list:
            # Construct the email for each recipient
            message = MIMEMultipart()
            message['From'] = "cestimesheet67@gmail.com"
            message['To'] = mail_to
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            # Send the email
            s.sendmail("cestimesheet67@gmail.com", mail_to, message.as_string())
            print(f'Project creation request email sent to {mail_to} successfully.')
    except Exception as e:
        print(f"Error sending email: {e}")
    finally:
        if server:
            server.quit()

def Project_creation_request_Notification(mail_to_list, project_id, requested_by):
    # Establish connection with SMTP server
    s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    s.login("cestimesheet67@gmail.com", "rmlomkpnujzzvlsy")

    # Set subject and email body
    subject = f"New Project Request - {project_id}"

    # Corrected body content with proper placeholders
    body = (
        # f"TEST MAIL PLEASE IGNORE\n\n"
        f"Dear Sir/Madam,\n\n"
        f"A new request has been made to create a project with the following details:\n\n"
        f"Project ID: {project_id}\n"
        f"Requested By: {requested_by}\n\n"
        "Thank you for your attention to this matter.\n\n"
        "Best regards,\n"
        "Centroid Engineering Solutions"
    )

    server = None  # Initialize server to ensure it's defined
    try:
        # Send email to each recipient in the mail_to_list
        for mail_to in mail_to_list:
            # Construct the email for each recipient
            message = MIMEMultipart()
            message['From'] = "cestimesheet67@gmail.com"
            message['To'] = mail_to
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            # Send the email
            s.sendmail("cestimesheet67@gmail.com", mail_to, message.as_string())
            print(f'Project creation request email sent to {mail_to} successfully.')

    except Exception as e:
        print(f"Error sending email: {e}")
    finally:
        if server:
            server.quit()

@app.route('/hours_edit/', methods=['GET', 'POST'])
def hours_edit():   
    if not session.get('logged_in'):
        return redirect(url_for('login')) 
    user = get_current_user()
    depart = get_department_code_by_username(user['name'])
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    from datetime import datetime, timedelta
    current_year = datetime.now().year
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 

    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        month = request.form.get('month')

    user_access = get_employee_access_control(user['name'])
    return render_template("admin_templates/projects/hours_edit.html",user_access=user_access,is_pm=is_pm, user=user,
                            usernames=usernames,department_code=department_code, current_year=current_year)

@app.route('/fetch_working_hours', methods=['POST'])
def fetch_working_hours():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    print("We are here in the data")
    db = get_database()
    cursor = db.cursor()
    data = request.get_json()
    employee_id = data.get('employee_id')
    month = data.get('month')
    year = data.get('year')

    query = """ SELECT entryID, section_code, projectID, departmentID, employeeID, workingDate, project_name, client, 
            formatted_date, hoursWorked, overtime_1_5, overtime_2_0, totalhours, total_cost 
        FROM workingHours WHERE employeeID = ? AND strftime('%m', formatted_date) = ? AND strftime('%Y', formatted_date) = ?ORDER BY formatted_date """


    # Use a cursor to execute the query and fetch results
    
    cursor.execute(query, (employee_id, month, year))
    rows = cursor.fetchall()

    # Format rows into dictionaries for JSON response
    results = [dict(zip([column[0] for column in cursor.description], row)) for row in rows]

    return jsonify(results)

@app.route('/update_working_hours', methods=['POST'])
def update_working_hours():
    data = request.get_json()  # Get the JSON data from the request
    selected_rows = data.get('updatedRows', [])

    if not selected_rows:
        return jsonify({'success': False, 'message': 'No data to update'})

    success_count = 0
    error_rows = []


    # Connect to the database
    db = get_database()
    cursor = db.cursor()
    # print(".......selected_rows.........",selected_rows)

    # Update the working hours for each selected row
    for row in selected_rows:
        employee_id = row['employee']
        formatted_date = row['formatted_date']
        newtotal = float(row['totalhr'])

        # Check if total hours for this employee on this date exceed 24 hours
        cursor.execute('''
            SELECT SUM(total_cost) 
            FROM workingHours 
            WHERE employeeID = ? AND formatted_date = ? AND entryID != ?
        ''', (employee_id, formatted_date, row['entryID']))
        total_existing_hours = cursor.fetchone()[0] or 0.0
  
        if total_existing_hours + newtotal <= 24.0:
            hours_worked = float(row['hoursWorked']) if row['hoursWorked'] else 0.0
            overhead1 = float(row['overtime1_5']) if row['overtime1_5'] else 0.0
            overhead2 = float(row['overtime2_0']) if row['overtime2_0'] else 0.0
            total_cost = round(hours_worked + (overhead1 * 1.5) + (overhead2 * 2.0), 2)
            # print("...row['entryID']...........",row['entryID'])

            # Update the working hours if not exceeding 24 hours
            cursor.execute("""
                UPDATE workingHours
                SET hoursWorked = ?, overtime_1_5 = ?, overtime_2_0 = ?, totalhours = ?, total_cost = ?
                WHERE entryID = ?
            """, (hours_worked, overhead1, overhead2, newtotal, total_cost, row['entryID']))
            db.commit()

            success_count += 1
        else:
            error_rows.append((employee_id, formatted_date, total_existing_hours + newtotal))
            continue  # Skip this row


    db.commit()

    # Construct the flash message
    flash_message = f"Successfully recorded {success_count} working hour entries."
    if error_rows:
        error_details = "; ".join([f"Employee {emp} on {date} ({hours} hours)" 
                                    for emp, date, hours in error_rows])
        flash_message += f" Some rows were skipped due to exceeding 24 hours: {error_details}."

    # Show flash message
    flash(flash_message, 'update_hr')

    return jsonify({'success': True, 'message': flash_message})

@app.route('/prj_hrs_view', methods=['GET', 'POST'])
@login_required
def prj_hrs_view():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.args.get('project_id', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    query = "SELECT project_members, pm FROM projects WHERE id = ?"
    cursor.execute(query, (project_id,))
    result = cursor.fetchone()

    if result:
        if result[0]:
            prj_members = result[0].split(',')
            prj_members = [member.strip() for member in prj_members]
        else:
            prj_members = []
        pm = result[1]
        if pm and pm not in prj_members:
            prj_members.append(pm)
        
        query_working_hours = """ SELECT DISTINCT employeeID FROM workingHours WHERE projectID = ? """
        cursor.execute(query_working_hours, (project_id,))
        working_employees = cursor.fetchall()
        
        for employee in working_employees:
            employee_id = employee[0]
            if employee_id not in prj_members:
                prj_members.append(employee_id)

        prj_members.sort()

    else:
        prj_members = []

    if request.method == 'POST':
        print("sairam")

    user_access = get_employee_access_control(user['name'])
    insights =[]
    department_codes = db.execute('SELECT DISTINCT department_code FROM admin_user').fetchall()
    sorted_department_codes = sorted([int(department_code[0]) for department_code in department_codes])
    # print("................sorted_department_codes.........",sorted_department_codes)
    return render_template('admin_templates/projects/prj_hrs_view.html', is_pm=is_pm, department_code=department_code,insights=insights,
                         prj_members=prj_members, project_details=project_details,user_access=user_access, user=user, project_id=project_id,
                         department_codes=sorted_department_codes)

@app.route('/prj_working_hours', methods=['GET', 'POST'])
def prj_working_hours():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        project_id = request.form.get('project_id')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        section_code = request.form.get('section_code')
        department_code = request.form.get('department_code')

        query = "SELECT * FROM workingHours WHERE 1=1"
        params = []
        sub_query = ""
        insight_quary = ""

        if section_code:
            query += " AND section_code = ?"
            sub_query += " AND section_code = ?"
            insight_quary += 'AND section_code = ?'
            params.append(section_code)

        if department_code:
            query += " AND departmentID = ?"
            sub_query += " AND departmentID = ?"
            insight_quary += 'AND departmentID = ?'
            params.append(department_code)

        if start_date:
            query += " AND formatted_date >= ?"
            sub_query += " AND formatted_date >= ?"
            insight_quary += 'AND formatted_date >= ?'
            params.append(start_date)

        if end_date:
            query += " AND formatted_date <= ?"
            sub_query += " AND formatted_date <= ?"
            insight_quary += " AND formatted_date <= ?"
            params.append(end_date)

        if employee_id and employee_id != "All":
            query += " AND employeeID = ?"
            sub_query += " AND employeeID = ?"
            insight_quary += " AND employeeID = ?"
            params.append(employee_id)

        if project_id and project_id != "ALL_Projects":
            query += " AND projectID = ?"
            sub_query += " AND projectID = ?"
            insight_quary += " AND projectID = ?"
            params.append(project_id)

        query += " ORDER BY formatted_date"

        db = get_database()
        cursor = db.cursor()
        cursor.execute(query, tuple(params))
        data = cursor.fetchall()

        project_hours_query = f"""SELECT projectID, SUM(hoursWorked) AS total_hours_per_project FROM workingHours WHERE 1=1 {insight_quary} GROUP BY projectID """
        project_hours_cursor = db.execute(project_hours_query, tuple(params))
        project_hours_result = project_hours_cursor.fetchall()
        
        project_ids = []
        hours_spent = []

        for row in project_hours_result:
            if row['projectID'] is not None and row['total_hours_per_project'] is not None:
                project_ids.append(row['projectID'])
                hours_spent.append(row['total_hours_per_project'])

        project_hours_data = { "project_ids": project_ids, "hours_spent": hours_spent }

        aggregate_query = f"""
            SELECT 
                COUNT(DISTINCT formatted_date) AS distinct_date_count,
                SUM(hoursWorked) AS total_hours,
                SUM(overtime_1_5) AS total_overtime_1_5,
                SUM(overtime_2_0) AS total_overtime_2_0,
                SUM(total_cost) AS total_cost
            FROM workingHours
            WHERE 1=1 {sub_query}
        """
        aggregate_cursor = db.execute(aggregate_query, tuple(params))
        aggregate_result = aggregate_cursor.fetchone()

        insights = {
            "distinct_date_count": aggregate_result["distinct_date_count"],
            "total_hours": aggregate_result["total_hours"],
            "total_overtime_1_5": aggregate_result["total_overtime_1_5"],
            "total_overtime_2_0": aggregate_result["total_overtime_2_0"],
            "total_cost": aggregate_result["total_cost"]
        }

        # Now for calculating the total sum across all departments
        total_hours_all_departments = 0
        total_days_all_departments = 0
        workload_by_date_dict = {}

        if employee_id == "All":
            # If all employees are selected, calculate for all departments combined
            employees_query = f"SELECT DISTINCT employeeID FROM workingHours WHERE projectID = {project_id}"
            cursor.execute(employees_query)
            employees = cursor.fetchall()

            for employee in employees:
                username = employee['employeeID']
                department_code = get_department_code_by_username(username)

                if department_code:
                    dept_query = f""" SELECT project_id, SUM(total) AS total_hours FROM pmtable WHERE department_code = ? AND project_id IN ({','.join(['?'] * len(project_ids))}) GROUP BY project_id   """
                    dept_params = [department_code] + project_ids
                    cursor.execute(dept_query, dept_params)
                    dept_data = cursor.fetchall()

                    for row in dept_data:
                        # total_hours_all_departments += row['total_hours']
                        total_days_all_departments += 1  # You can adjust based on your data if needed

            query = """
                SELECT SUM(total) AS total_hours 
                FROM pmtable 
                WHERE project_id = ? 
                AND (department_code >= 1000 AND department_code <= 1999 
                    OR department_code >= 10 AND department_code <= 100)
            """


            cursor.execute(query, (project_id,))
            result = cursor.fetchone()
            total_hours_all_departments = result[0] if result and result[0] is not None else 0  # Handle NULL case
            
            workload_by_date_query = """
                SELECT 
                    employeeID, 
                    formatted_date, 
                    SUM(total_cost) AS total_hours
                FROM workingHours
                WHERE 1=1 {insight_quary}
                GROUP BY employeeID, formatted_date
                ORDER BY employeeID, formatted_date
            """.format(insight_quary=insight_quary)

            cursor.execute(workload_by_date_query, tuple(params))
            workload_by_date = cursor.fetchall()
            
            for row in workload_by_date:
                employee_id = row['employeeID']
                if employee_id not in workload_by_date_dict:
                    workload_by_date_dict[employee_id] = []
                workload_by_date_dict[employee_id].append({
                    "date": row['formatted_date'],
                    "hours": row['total_hours']
                })

            highest_workload_query = """ SELECT formatted_date, SUM(total_cost) AS total_cost FROM workingHours WHERE projectID = ? GROUP BY formatted_date ORDER BY total_cost DESC LIMIT 1; """

            # Execute the query to get the highest workload data
            cursor.execute(highest_workload_query, (project_id,))
            highest_workload_data = cursor.fetchone()

            if highest_workload_data:
                highest_workload_date = highest_workload_data['formatted_date']
                highest_workload_hours = highest_workload_data['total_cost']
            else:
                highest_workload_date = None  # Or you can set this to '0' if preferred
                highest_workload_hours = 0

        else:
            # If a specific employee is selected, calculate for that employee's department
            department_code = get_department_code_by_username(employee_id)

            if department_code:
                # print("............department_code........",department_code)
                dept_query = f""" SELECT project_id, SUM(total) AS total_cost FROM pmtable WHERE department_code = ? AND project_id IN ({','.join(['?'] * len(project_ids))}) GROUP BY project_id """
                dept_params = [department_code] + project_ids
                cursor.execute(dept_query, dept_params)
                dept_data = cursor.fetchall()

                for row in dept_data:
                    total_hours_all_departments += row['total_cost']
                    total_days_all_departments += 1  # You can adjust based on your data if needed

                workload_by_date_query = """ SELECT  formatted_date,  SUM(total_cost) AS total_cost FROM workingHours WHERE employeeID = ? {insight_quary} GROUP BY formatted_date ORDER BY formatted_date """.format(insight_quary=insight_quary)
                cursor.execute(workload_by_date_query, (employee_id, *params))
                workload_by_date = cursor.fetchall()
                workload_by_date_dict = { employee_id: [{"date": row["formatted_date"], "hours": row["total_cost"]} for row in workload_by_date]  }


            highest_workload_query = """ SELECT formatted_date, SUM(total_cost) AS total_cost FROM workingHours WHERE employeeID = ? AND projectID = ? GROUP BY formatted_date ORDER BY total_cost DESC LIMIT 1; """

            # Execute the query to get the highest workload data
            cursor.execute(highest_workload_query, (employee_id,project_id))

            highest_workload_data = cursor.fetchone()

            if highest_workload_data:
                highest_workload_date = highest_workload_data['formatted_date']
                highest_workload_hours = highest_workload_data['total_cost']
            else:
                highest_workload_date = None  # Or you can set this to '0' if preferred
                highest_workload_hours = 0

        query = "SELECT start_time, end_time FROM projects WHERE id = ?"
        cursor.execute(query, [project_id])
        project_data = cursor.fetchone()

        if project_data:
            start_time = project_data['start_time']
            end_time = project_data['end_time']
            total_days, days_active, days_left = calculate_days_left_and_active(start_time, end_time)

        avg_hours_per_day_all_departments = total_hours_all_departments / days_active if days_active > 0 else 0
        # print("......insights...............\n",insights)
        return jsonify({
            "data": [dict(row) for row in data],
            "insights": insights,
            "project_ids": project_ids,
            "hours_spent": hours_spent,
            "total_hours_all_departments": total_hours_all_departments,
            "avg_hours_per_day_all_departments": avg_hours_per_day_all_departments,
            "total_days": total_days,
            "days_active": days_active ,
            "days_left": days_left,
            "workload_by_date_dict" : workload_by_date_dict,
            "highest_workload_date" :highest_workload_date,
            "highest_workload_hours" :highest_workload_hours,
        })

def calculate_days_left_and_active(start_date, end_date):
    from datetime import datetime
    current_date = datetime.now()
    
    # Convert start and end date strings to datetime objects
    start_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_date = datetime.strptime(end_date, '%Y-%m-%d')

    # Calculate the total allocated days
    total_days = (end_date - start_date).days

    # Calculate the current day based on the start date
    days_active = (current_date - start_date).days
    days_left = total_days - days_active  # Number of days left for the project

    return total_days, days_active, days_left

@app.route('/fetch_po_items_for_Material_Receipt/<po_number>', methods=['GET'])
def fetch_po_items_for_Material_Receipt(po_number):
    db = get_database()
    cursor = db.cursor()

    # Query to get rows from Material_Receipt table for the given PO number
    query_material_receipt = """SELECT item_name, part_number, SUM(quantity) as total_received FROM Material_Receipt  WHERE po_number = ?  GROUP BY item_name, part_number"""
    cursor.execute(query_material_receipt, (po_number,))
    material_receipt_items = cursor.fetchall()

    # Store received quantities using only item name as the key, and accumulate totals regardless of part_no
    received_quantities = {}

    for item_name, part_no, total_received in material_receipt_items:
        # Use a tuple (item_name, part_no) as the key, but replace None/empty part_no with a placeholder
        key = (item_name.strip(), (part_no or "N/A").strip())

        if key in received_quantities:
            received_quantities[key] += total_received 
        else:
            received_quantities[key] = total_received 

    # Query to fetch items from po_items table for the given PO number, including excepted_date and status
    query_po_items = """SELECT id, item, uom, quantity, Part_No, excepted_date, status FROM po_items WHERE PO_number = ?"""
    cursor.execute(query_po_items, (po_number,))
    po_items = cursor.fetchall()

    # Build the item list with pending quantities for each item
    item_list = []
    for id, item_name, uom, ordered_quantity, part_no, excepted_date, status in po_items:
        # Use a tuple (item_name, part_no) as the key to retrieve the received quantity
        key = (item_name.strip(), (part_no or "N/A").strip())

        # Get the total received quantity for the current item (default to 0 if not found)
        received_quantity = received_quantities.get(key, 0)

        # Calculate the pending quantity
        pending_quantity = max(ordered_quantity - received_quantity, 0)  # Ensure it's non-negative

        # Handle empty or NULL excepted_date by setting it to None or empty string
        excepted_date = excepted_date if excepted_date else None  # You can set '' if you prefer empty string

        item_list.append({
            'id' : id,
            'item': item_name,
            'uom': uom,
            'ordered_quantity': ordered_quantity,
            'part_no': part_no or "N/A",  # Handle missing part_no gracefully
            'received_quantity': received_quantity,
            'pending_quantity': pending_quantity,  # Add pending quantity to the dictionary
            'excepted_date': excepted_date,  # Add excepted_date to the dictionary, will be None if empty
            'status': status  # Add status to the dictionary
        })


    # Query to get supplier name from created_po table
    query_supplier = """SELECT Supplier_Name FROM created_po WHERE PO_no = ?"""
    cursor.execute(query_supplier, (po_number,))
    supplier = cursor.fetchone()

    supplier_name = supplier[0] if supplier else "Unknown"
    # print("Supplier Name:", supplier_name)

    # Return the combined response as JSON
    return jsonify({'items': item_list, 'supplier_name': supplier_name})

@app.route('/check_do_number_supplier', methods=['POST'])
def check_do_number_supplier():
    data = request.json
    do_number = data.get('do_number')
    supplier_name = data.get('supplier_name')
    db = get_database()  
    cursor = db.cursor()
    cursor.execute( "SELECT COUNT(*) FROM Delivery_Order WHERE do_number = ? AND supplier_name = ?", (do_number, supplier_name))
    result = cursor.fetchone()[0]
    return jsonify({'exists': result > 0})

@app.route('/Material_Receipt', methods=['GET', 'POST'])
@login_required
def Material_Receipt():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    db = get_database()  
    cursor = db.cursor()

    # Fetch delivery data with filename included
    cursor = db.execute("""
        SELECT 
            d.po_number,
            d.do_number,
            d.supplier_name,
            d.status AS do_status,
            d.filename,  -- Include filename here
            MAX(m.received_date) AS received_date,
            m.received_by,
            m.received_on_behalf_of,
            cp.do_staus AS po_status
        FROM 
            Delivery_Order d
        LEFT JOIN 
            Material_Receipt m ON d.do_number = m.do_number AND d.supplier_name = m.supplier_name
        LEFT JOIN 
            created_po cp ON d.po_number = cp.PO_no
        GROUP BY 
            d.po_number, d.do_number, d.supplier_name, d.status, d.filename
        ORDER BY 
            d.po_number DESC, d.do_number
    """)
    delivery_data = cursor.fetchall()

    # Group data by PO number
    from collections import defaultdict
    grouped_data = defaultdict(lambda: {'po_status': '', 'supplier_name': '', 'do_items': []})
    # print(".....delivery_data................",delivery_data)

    for row in delivery_data:
        # print(".....row................",row['filename'])

        po = row['po_number']
        grouped_data[po]['do_staus'] = row['po_status']
        grouped_data[po]['supplier_name'] = row['supplier_name']
        grouped_data[po]['do_items'].append(row)

    # Get list of usernames
    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])

    # Get user access
    user_access = get_employee_access_control(user['name'])

    # Get PO numbers that are not closed
    cursor.execute("SELECT PO_no FROM created_po WHERE LOWER(do_staus) != 'closed' ORDER BY id DESC")
    PO_Numbers = [row[0] for row in cursor.fetchall()]

    return render_template('admin_templates/projects/Material_Receipt.html',
                           user_access=user_access,
                           department_code=department_code,
                           grouped_data=grouped_data,
                           user=user,
                           usernames=usernames,
                           PO_Numbers=PO_Numbers)

@app.route('/update_material_receipt_to_add',methods=['POST'])
@login_required
def update_material_receipt_to_add():
    print(request.form)  # DEBUGGING
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_database()  
    cursor = db.cursor()
    user = get_current_user()
    po_number = request.form.get('po_number')
    comments = request.form.get('comments')
    supplier_name = request.form.get('supplier_name')
    do_number = request.form.get('do_number')
    selected_items = request.form.getlist('selected_items[]')
    item_names = request.form.getlist('item_name[]')
    ids = request.form.getlist('id[]')
    part_numbers = request.form.getlist('part_no[]')
    uoms = request.form.getlist('uom[]')
    pendings = request.form.getlist('pending[]')
    Received_date = request.form.get('Received_date')
    Received_by = request.form.get('Received_by')
    received_quantities = request.form.getlist('received_quantity[]')

    attachment = request.files.get('attachment') 
    if attachment:
        upload_dir = 'docment_data/Material Receipts'
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir) 

        file_name, file_extension = os.path.splitext(attachment.filename) 
        new_filename = f"{supplier_name}_{do_number}{file_extension}" 
        filename = os.path.join(upload_dir, new_filename)
        attachment.save(filename)
    else:
        new_filename = None  
        print("No file uploaded.")


    try:
        cursor.execute('''SELECT id FROM Delivery_Order WHERE do_number = ? AND supplier_name = ?''', (do_number, supplier_name))
        delivery_order = cursor.fetchone()

        if not delivery_order:
            cursor.execute('''INSERT INTO Delivery_Order (do_number,po_number, supplier_name, delivery_date, comments, filename) VALUES (?, ?, ?, ?, ?, ?)''', 
                           (do_number,po_number, supplier_name, Received_date, comments,new_filename))  # Assuming first received date as delivery date
            db.commit()

    except sqlite3.Error as e:
        flash(f"Error inserting into Delivery_Order: {str(e)}", 'mat_receive_error')
        db.rollback()
        return redirect(url_for('Material_Receipt'))


    for idx in range(len(item_names)):
        part_no = part_numbers[idx].strip() if part_numbers[idx] else None
        id = ids[idx]
        uom = uoms[idx]
        pending = pendings[idx]
        item_name = item_names[idx]
        received_qty = received_quantities[idx]

        if received_qty != '':
            try:
                cursor.execute('''INSERT INTO Material_Receipt (do_number, supplier_name, po_number, item_name, part_number,uom,
                                received_date, received_on_behalf_of, received_by, quantity,item_ref_code,filename)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)''',
                    (do_number, supplier_name, po_number, item_name, part_no,uom, Received_date, user['name'], Received_by, received_qty,id,new_filename))
                db.commit()
            except sqlite3.IntegrityError:
                flash(f"Duplicate entry for {item_name} with PO number {po_number}.", 'mat_receive_error')
                db.rollback()
            except sqlite3.Error as e:
                flash(f"Error inserting into Material_Receipt: {str(e)}", 'mat_receive_error')
                db.rollback()
    
    cursor.execute('''SELECT id, quantity FROM po_items WHERE PO_number = ?''', (po_number,))
    ordered_items = cursor.fetchall()
    all_received = True  # Track if all items are fully received
    for id, ordered_qty in ordered_items:
        cursor.execute('''SELECT SUM(quantity) FROM Material_Receipt WHERE po_number = ? AND item_ref_code = ?''', (po_number, id))
        received_qty = cursor.fetchone()[0] or 0
        if received_qty < ordered_qty:
            all_received = False  # Not fully received

    new_status = "Closed" if all_received else "Partial"

    try:
        cursor.execute('''UPDATE created_po SET do_staus = ? WHERE PO_no = ?''', (new_status, po_number))
        if new_status == 'Closed':
            query = "SELECT payment_status FROM created_po WHERE PO_no = ?"
            payment_status = db.execute(query, (po_number,)).fetchone()[0]

            if payment_status == 'Closed':
                update_query = "UPDATE created_po SET status = ? WHERE PO_no = ?"
                db.execute(update_query, ('Closed', po_number))
                db.commit()

        db.commit()
    
    except sqlite3.Error as e:
        flash(f"Error updating Delivery_Order status: {str(e)}", 'mat_receive_error')
        db.rollback()

        query_po_items = """SELECT id, item, quantity, Part_No FROM po_items WHERE PO_number = ?"""
        cursor = db.execute(query_po_items, (po_number,))
        po_items = cursor.fetchall()
        for item in po_items:
            item_id = item['id']
            item_name = item['item']
            part_no = item['Part_No']
            ordered_quantity = item['quantity']
            query_received_quantity = """ SELECT item_ref_code, SUM(quantity) as received_qty FROM Material_Receipt WHERE po_number = ? AND item_ref_code = ? 
                                            GROUP BY item_ref_code """
            cursor = db.execute(query_received_quantity, (po_number, item_id))
            received_data = cursor.fetchone()
            if received_data is None:
                total_received = 0
            else:
                total_received = received_data['received_qty'] 
            if total_received >= ordered_quantity:
                new_status = 'Closed'  
            else:
                new_status = 'Partial'  
            query_update_status = """ UPDATE po_items SET status = ? WHERE id = ? """
            db.execute(query_update_status, (new_status, item_id))
            db.commit()  

        db.commit()

        flash('Material receipt updated successfully!', 'mat_receive_success')

    return redirect(url_for('Material_Receipt'))

@app.route('/get_mat_details')
def get_mat_details():
    do_number = request.args.get('doNumber')
    supplier_name = request.args.get('supplierName')

    db = get_database()
    cursor = db.cursor()

    # Fetch Delivery Order details
    cursor.execute("""
        SELECT id, do_number, supplier_name, delivery_date, status, po_number, comments
        FROM Delivery_Order
        WHERE do_number = ? AND supplier_name = ?
    """, (do_number, supplier_name))
    delivery_order = cursor.fetchone()

    if not delivery_order:
        return jsonify({'success': False, 'message': 'Delivery Order not found'})

    # Fetch associated Material Receipt records
    cursor.execute(""" SELECT id, do_number, supplier_name, uom, po_number, item_name, part_number,
               received_date, received_by, received_on_behalf_of, quantity, item_ref_code
        FROM Material_Receipt
        WHERE do_number = ? AND supplier_name = ?
    """, (do_number, supplier_name))
    material_receipts = cursor.fetchall()

    # Format the result as a dictionary
    result = {
        'success': True,
        'delivery_order': {
            'id': delivery_order[0],
            'do_number': delivery_order[1],
            'supplier_name': delivery_order[2],
            'delivery_date': delivery_order[3],
            'status': delivery_order[4],
            'po_number': delivery_order[5],
            'comments': delivery_order[6]
        },
        'material_receipts': [
            {
                'id': row[0],
                'do_number': row[1],
                'supplier_name': row[2],
                'uom': row[3],
                'po_number': row[4],
                'item_name': row[5],
                'part_number': row[6],
                'received_date': row[7],
                'received_by': row[8],
                'received_on_behalf_of': row[9],
                'quantity': row[10],
                'item_ref_code': row[11]
            }
            for row in material_receipts
        ]
    }

    return jsonify(result)

@app.route('/delete_do', methods=['DELETE'])
def delete_do():
    do_number = request.args.get('do_number')
    supplier_name = request.args.get('supplier_name')

    if not do_number or not supplier_name:
        return jsonify({'success': False, 'message': 'Missing DO Number or Supplier Name'})

    try:
        db = get_database()
        cursor = db.cursor()
        # Delete from Delivery_Order (Material_Receipt rows will be deleted automatically via ON DELETE CASCADE)
        cursor.execute("""
            DELETE FROM Delivery_Order 
            WHERE do_number = ? AND supplier_name = ?
        """, (do_number, supplier_name))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/docment_data/Material Receipts/<path:filename>')
def view_do_file(filename):
    # directory = os.path.abspath(r'docment_data\Material Receipts')
    directory = os.path.abspath('/home/CES/docment_data/Material Receipts')
    
    # List of common file extensions
    extensions = [
    '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Images
    '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',  # Documents and spreadsheets
    '.html', '.htm', '.xml', '.json',  # Web and data files
    '.zip', '.tar', '.gz', '.rar',  # Archive files
    '.mp3', '.wav', '.ogg',  # Audio files
    '.mp4', '.avi', '.mkv', '.mov', '.webm',  # Video files
    '.svg', '.eps', '.ai',  # Vector images
    '.psd', '.indd',  # Adobe files (Photoshop, InDesign)
    '.epub', '.mobi', '.azw3',  # Ebook formats
    '.pptx', '.key',  # Presentation files
    '.xlsx', '.ods',  # Spreadsheet formats
    '.json', '.yaml',  # Configuration and data files
    '.md', '.rst',  # Markup files
    '.exe', '.msi', '.dmg',  # Executables and install files
    ]

    
    # Try each extension until we find the correct one
    for ext in extensions:
        file_path = os.path.join(directory, filename )
        print(f"Checking file path: {file_path}")
        
        if os.path.exists(file_path):
            return send_from_directory(directory, filename, as_attachment=False)
    
    return "File not found", 404


#------------------------------------------------------------------------Resources--------------------------------------------------------------------

@app.route('/resources', methods=['GET', 'POST'])
@login_required
def resources():
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    
    if request.method == 'POST':

        # Get the checkbox data from the request
        data = request.get_json()
        cursor.execute("SELECT description FROM resource_type")
        existing_descriptions = [row[0] for row in cursor.fetchall()]

        cursor.execute('PRAGMA table_info(resource_type)')
        column_info = cursor.fetchall()
        column_names = [col[1] for col in column_info if col[1] not in ['id', 'description']]  # Exclude 'id' and 'description'

        try:

            # Iterate over the data and update or insert dynamically
            for work_desc, designations in data.items():
                
                for trade, check_value in designations.items():
                    # Check if the current designation (description) exists
                    if work_desc in existing_descriptions:

                        query = f'''UPDATE resource_type SET "{trade}" = ?  WHERE description = ?;'''
                        cursor.execute(query, (check_value, work_desc))


            # Commit the changes
            db.commit()  # Commit the transaction
            flash("Criteria has been updated successfully!", "Criteria_success")
            return jsonify({"message": "Criteria has been updated successfully!"}), 200

        except Exception as e:
            db.rollback()  # Rollback in case of error
            flash(f"Something went wrong while saving the changes! {e}", "Criteria_error")
            return jsonify({"error": str(e)}), 500

    cursor.execute("SELECT * FROM resource_type")
    rows = cursor.fetchall()
    # Get column headers (designations), excluding 'id' and 'description'
    column_names = [desc[0] for desc in cursor.description][2:]
    # Prepare data structure: {work_desc: {designation: 'On'/'Off'}}
    table_data = {}
    for row in rows:
        work_desc = row[1]  # Work description
        table_data[work_desc] = {
            col: row[i + 2] for i, col in enumerate(column_names)
        }

    # Fetch department code and user access control
    department_code = get_department_code_by_username(user['name'])
    user_access = get_employee_access_control(user['name'])
    show = 'pr'


    return render_template( 'admin_templates/Resources/rindex.html', user_access=user_access,department_code=department_code, user=user,
                designations=column_names, row_headers=list(table_data.keys()), table_data=table_data, show = show)

#-----------------------------------------------------------------------Planner--------------------------------------------------------------------

@app.route('/planner', methods=["POST", "GET"])
@login_required
def planner():

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    db = get_database()
    cursor = db.cursor()
    user_access = get_employee_access_control(user['name'])
    cursor.execute('SELECT username FROM admin_user WHERE register = 1')

    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 



    cursor.execute('SELECT * FROM user_tasks ORDER BY due_date')
    tasks = [
        {
            'id': row[0],
            'task_name': row[1],
            'assigend_to': row[2],
            'bucket': row[3],
            'progress': row[4],
            'priority': row[5],
            'start_date': row[6],
            'due_date': row[7],
            'label': row[8],
            'notes': row[9],
            'checklist': row[10],
            'attachemnt_file': row[11],
            'created_by': row[12],
            'created_date': row[13],
        }
        for row in cursor.fetchall()
    ]


    # Fetch active projects (status NOT 'Closed')
    cursor.execute("SELECT id, project_name FROM projects WHERE status IS NULL OR status != 'Closed' ORDER BY id DESC")
    active_projects = cursor.fetchall()


    # Format: ['1 - Project A', '2 - Project B', ...]
    project_options = [f"{row[0]} - {row[1]}" for row in active_projects]

    print("..........project_options...........",project_options)
    cursor.execute("SELECT DISTINCT bucket FROM user_tasks WHERE bucket IS NOT NULL AND bucket != ''")
    buckets = sorted(set([row[0] for row in cursor.fetchall()]))

    cursor.execute("SELECT DISTINCT label FROM user_tasks WHERE label IS NOT NULL AND label != ''")
    labels = sorted(set([row[0] for row in cursor.fetchall()]))
    print("..........buckets...........",buckets)
    print("..........labels...........",labels)

    return render_template('admin_templates/planner/planner.html', usernames=usernames, user=user,user_access=user_access,
                           buckets=buckets,labels=labels,project_options=project_options,department_code=department_code,tasks=tasks)

from flask import request, jsonify
import datetime
import os

@app.route('/create_task', methods=['POST'])
def create_task():

    db = get_database()
    cursor = db.cursor()
    task_name = request.form.get('taskName')
    assigend_to = request.form.get('assigend_to')  # Multiple names as comma-separated string
    bucket = request.form.get('bucket')
    progress = request.form.get('progress')
    priority = request.form.get('priority')
    start_date = request.form.get('startDate') or None
    due_date = request.form.get('dueDate') or None
    label = request.form.get('label')
    notes = request.form.get('notes')
    checklist = request.form.getlist('checklist[]')
    checklist_str = json.dumps(checklist)    
    print("........checklist........",checklist_str)
    created_by = get_current_user()  # Replace with actual user
    created_date = datetime.datetime.now().strftime('%Y-%m-%d')

    try:
        db.execute("""
            INSERT INTO user_tasks (
                task_name, assigend_to, bucket, progress, priority,
                start_date, due_date, label, notes, checklist,
             created_by, created_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            task_name, assigend_to, bucket, progress, priority,
            start_date, due_date, label, notes, checklist_str, created_by['name'], created_date
        ))
        db.commit()
        return jsonify(success=True)
    except Exception as e:
        print('Error creating task:', e)
        return jsonify(success=False)


@app.route('/update_task_status/<int:task_id>', methods=['POST'])
def update_task_status(task_id):
    db = get_database()
    cursor = db.cursor()

    new_status = request.json.get('status', 'Not Started')

    try:
        cursor.execute("UPDATE user_tasks SET progress = ? WHERE id = ?", (new_status, task_id))
        db.commit()
        return jsonify(success=True)
    except Exception as e:
        print("Error updating task status:", e)
        return jsonify(success=False)


@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    db = get_database()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_tasks WHERE id = ?", (task_id,))
        db.commit()
        return jsonify(success=True)
    except Exception as e:
        print('Error deleting task:', e)
        return jsonify(success=False)

@app.route('/get_task/<int:task_id>')
def get_task(task_id):
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user_tasks WHERE id = ?", (task_id,))
    row = cursor.fetchone()
    if row:
        return jsonify(task=dict(row))  # convert sqlite Row to dict
    return jsonify(task=None), 404


@app.route('/update_task/<int:task_id>', methods=['POST'])
def update_task(task_id):
    db = get_database()
    cursor = db.cursor()

    task_name = request.form.get('taskName')
    assigend_to = request.form.get('assigend_to')
    bucket = request.form.get('bucket')
    progress = request.form.get('progress')
    priority = request.form.get('priority')
    start_date = request.form.get('startDate')
    due_date = request.form.get('dueDate')
    label = request.form.get('label')
    notes = request.form.get('notes')
    checklist = request.form.getlist('checklist[]')
    checklist_str = json.dumps(checklist)

    try:
        cursor.execute("""
            UPDATE user_tasks
            SET task_name = ?, assigend_to = ?, bucket = ?, progress = ?, priority = ?,
                start_date = ?, due_date = ?, label = ?, notes = ?, checklist = ?
            WHERE id = ?
        """, (
            task_name, assigend_to, bucket, progress, priority,
            start_date, due_date, label, notes, checklist_str, task_id
        ))
        db.commit()
        return jsonify(success=True)
    except Exception as e:
        print("Error updating task:", e)
        return jsonify(success=False)


#------------------------------------------------------------------------settings--------------------------------------------------------------------

@app.route('/settings')
@login_required
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT username FROM admin_user ')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 
    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/settings/index.html',user_access=user_access,department_code=department_code, user=user, usernames=usernames)

@app.route('/Archived')
@login_required
def Archived():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])

    # Get usernames
    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower()) 

    user_access = get_employee_access_control(user['name'])
    cursor.execute("SELECT id, project_name FROM projects WHERE status = 'Closed' ORDER BY id ASC")
    archived_projects = cursor.fetchall()


    return render_template('admin_templates/settings/Archived.html',user_access=user_access,department_code=department_code,user=user,
                           usernames=usernames,archived_projects=archived_projects)



@app.route('/update_project_status_js', methods=['POST'])
def update_project_status_js():
    data = request.get_json()
    project_id = data.get('project_id')
    new_status = data.get('status')

    try:
        db = get_database()
        cursor = db.cursor()
        cursor.execute("UPDATE projects SET status = ? WHERE id = ?", (new_status, project_id))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/controls', methods=['GET', 'POST'])
@login_required
def controls():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    
    # Get projectId from query parameters
    project_id = request.args.get('projectId', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone() 
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    # cursor.execute('SELECT username FROM admin_user WHERE department_code != 1000')
    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    employee_details= None 

    if request.method == 'POST':

        get_employee_controls = request.form.get('get_employee_controls')
        update_access = request.form.get('update_access')

        if update_access:
            # Collect all form data
            accounts = request.form.get('accounts_section')
            acc_expenses = request.form.get('expenses')
            acc_clients = request.form.get('clients')
            acc_vendors = request.form.get('vendors')
            profile = request.form.get('profile_section')
            prof_dashboard = request.form.get('profile_dashboard')
            prof_personal_details = request.form.get('personal_details')
            prof_leaves = request.form.get('leaves')
            prof_courses = request.form.get('courses')
            prof_pay_slip = request.form.get('pay_slip')
            prof_assets = request.form.get('assets')
            profile_Approvals_section = request.form.get('profile_Approvals_section')
            profile_Payment_Req_approval = request.form.get('profile_Payment_Req_approval')


            project = request.form.get('project_section')
            proj_dashboard = request.form.get('project_overview')
            proj_project_summary = request.form.get('proj_project_summary')
            proj_pr_po_project = request.form.get('proj_pr_po_project')
            proj_project_edit = request.form.get('proj_project_edit')
            proj_timesheet = request.form.get('proj_timesheet')
            proj_claims = request.form.get('proj_claims')
            proj_enquiry = request.form.get('proj_enquiry')
            proj_edit_enquiry = request.form.get('proj_edit_enquiry')
            proj_time_edit = request.form.get('proj_time_edit')
            proj_hours_view = request.form.get('proj_hours_view')
            proj_pr_po = request.form.get('proj_pr_po')
            proj_pr_edit = request.form.get('proj_pr_edit')
            proj_po_edit = request.form.get('proj_po_edit')
            proj_prj_request = request.form.get('proj_prj_request')
            # print(proj_pr_po,proj_pr_edit,proj_po_edit)
            purchase = request.form.get('purchase_section')
            pur_suppliers = request.form.get('pur_suppliers')
            pur_purchaser = request.form.get('pur_purchaser')
            
            pur_pr_approve = request.form.get('pur_pr_approve')
            pur_pr_process = request.form.get('pur_pr_process')
            pur_pr_create = request.form.get('pur_pr_create')
            pur_pr_edit = request.form.get('pur_pr_edit')
            pur_pr_delete = request.form.get('pur_pr_delete')
            pur_po_edit = request.form.get('pur_po_edit')
            pur_po_print = request.form.get('pur_po_print')
            pur_po_delete = request.form.get('pur_po_delete')
            pur_pr = request.form.get('pur_pr')
            pur_po = request.form.get('pur_po')
            Material_Receipt = request.form.get('Material_Receipt')
            DO_Delete = request.form.get('DO_Delete')
            

            # print(pur_pr_approve, pur_pr_process, pur_pr_create, pur_pr_edit, pur_pr_delete, pur_po_edit, pur_po_print, pur_po_delete, pur_pr, pur_po)

            hr = request.form.get('hr_section')
            hr_add = request.form.get('hr_add')
            hr_course = request.form.get('add_course')
            hr_leave = request.form.get('add_leave')
            hr_asset = request.form.get('add_asset')
            hr_option1 = request.form.get('add_option1')
            hr_leave_approvals = request.form.get('leave_approvals')
            hr_profile = request.form.get('profile_update')
            hr_update_bio = request.form.get('update_bio')
            hr_update_courses = request.form.get('update_courses')
            hr_update_assets = request.form.get('update_assets')
            hr_option2 = request.form.get('hr_option2')

            hr_leave_Dashboard = request.form.get('hr_leave_Dashboard')
            hr_leave_pending_Approval = request.form.get('hr_leave_pending_Approval')
            hr_leave_stats = request.form.get('hr_leave_stats')
            hr_leave_allocation = request.form.get('hr_leave_allocation')
            print("....hr_leave_allocation..........",hr_leave_allocation)

            # Check if the employee exists
            cursor.execute('SELECT COUNT(1) FROM access_control WHERE Employee_ID = ?', (update_access,))
            exists = cursor.fetchone()[0]

            if exists:
                # Update query
                query = ''' UPDATE access_control SET accounts = ?, acc_expenses = ?, acc_clients = ?, acc_vendors = ?, profile = ?,
                    prof_dashboard = ?, prof_personal_details = ?, prof_leaves = ?, prof_courses = ?, prof_pay_slip = ?, prof_assets = ?,profile_Approvals_section=?, profile_Payment_Req_approval=?, project = ?, proj_dashboard = ?, proj_project_summary = ?,
                    proj_pr_po_project = ?, proj_project_edit = ?, proj_timesheet = ?, proj_claims = ?, proj_enquiry = ?, proj_edit_enquiry = ?, proj_time_edit = ?, proj_hours_view = ?, proj_pr_po = ?, proj_pr_edit = ?, 
                    proj_po_edit = ?, proj_prj_request = ?, purchase = ?, pur_suppliers = ?,  pur_purchaser = ?, pur_pr_approve = ?,  pur_pr_process = ?, pur_pr_create = ?,  pur_pr_edit = ?,  pur_pr_delete = ?,  pur_po_edit = ?,  pur_po_print = ?,  pur_po_delete  = ?, pur_pr = ?,pur_po =?,Material_Receipt=?, DO_Delete=?,
                    hr = ?, hr_add = ?, hr_course = ?, hr_leave = ?, hr_asset = ?, hr_option1 = ?, hr_leave_approvals = ?, hr_profile = ?, hr_update_bio = ?, hr_update_courses = ?, hr_update_assets = ?, hr_option2 = ?,
                    hr_leave_Dashboard = ?,hr_leave_pending_Approval=?, hr_leave_stats=?, hr_leave_allocation=?  WHERE Employee_ID = ? '''
                cursor.execute(query, (accounts, acc_expenses, acc_clients, acc_vendors, profile, prof_dashboard, prof_personal_details, prof_leaves, prof_courses, prof_pay_slip, prof_assets,
                    profile_Approvals_section, profile_Payment_Req_approval,project, proj_dashboard, proj_project_summary, proj_pr_po_project, proj_project_edit, proj_timesheet, proj_claims, proj_enquiry, proj_edit_enquiry, proj_time_edit, proj_hours_view, proj_pr_po, proj_pr_edit, proj_po_edit,proj_prj_request,
                    purchase,pur_suppliers,pur_purchaser, pur_pr_approve , pur_pr_process , pur_pr_create , pur_pr_edit , pur_pr_delete , pur_po_edit , pur_po_print , pur_po_delete, pur_pr,pur_po, Material_Receipt, DO_Delete,
                    hr, hr_add, hr_course, hr_leave, hr_asset, hr_option1, hr_leave_approvals, hr_profile, hr_update_bio, hr_update_courses, hr_update_assets, hr_option2,
                    hr_leave_Dashboard,hr_leave_pending_Approval, hr_leave_stats, hr_leave_allocation, update_access))
            else:
                # Insert query
                query = ''' INSERT INTO access_control (Employee_ID, accounts, acc_expenses, acc_clients, acc_vendors, profile, prof_dashboard, prof_personal_details, prof_leaves, prof_courses, prof_pay_slip,
                    prof_assets, profile_Approvals_section, profile_Payment_Req_approval, project, proj_dashboard, proj_project_summary, proj_pr_po_project, proj_project_edit, proj_timesheet, proj_claims, proj_enquiry, proj_edit_enquiry,
                    proj_time_edit, proj_hours_view, proj_pr_po, proj_pr_edit, proj_po_edit,proj_prj_request, purchase,pur_suppliers,pur_purchaser, pur_pr_approve , pur_pr_process , 
                    pur_pr_create , pur_pr_edit , pur_pr_delete , pur_po_edit , pur_po_print , pur_po_delete ,pur_pr,pur_po, Material_Receipt, DO_Delete,
                    hr, hr_add, hr_course, hr_leave, hr_asset, hr_option1, hr_leave_approvals, hr_profile, hr_update_bio,
                    hr_update_courses, hr_update_assets, hr_option2,hr_leave_Dashboard,hr_leave_pending_Approval, hr_leave_stats, hr_leave_allocation) VALUES 
                    (?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
                cursor.execute(query, (update_access, accounts, acc_expenses, acc_clients, acc_vendors, profile, prof_dashboard, prof_personal_details, prof_leaves, prof_courses, prof_pay_slip,
                    prof_assets, profile_Approvals_section, profile_Payment_Req_approval, project, proj_dashboard, proj_project_summary, proj_pr_po_project, proj_project_edit, proj_timesheet, proj_claims, proj_enquiry, proj_edit_enquiry,
                    proj_time_edit, proj_hours_view, proj_pr_po, proj_pr_edit, proj_po_edit,proj_prj_request, purchase,pur_suppliers,pur_purchaser, pur_pr_approve , pur_pr_process , 
                    pur_pr_create , pur_pr_edit , pur_pr_delete , pur_po_edit , pur_po_print , pur_po_delete ,pur_pr,pur_po,Material_Receipt, DO_Delete,
                    hr, hr_add, hr_course, hr_leave, hr_asset, hr_option1, hr_leave_approvals, hr_profile, hr_update_bio,
                    hr_update_courses, hr_update_assets, hr_option2,hr_leave_Dashboard,hr_leave_pending_Approval, hr_leave_stats, hr_leave_allocation))

            db.commit()
            flash(f'Access Control for {update_access} is being updated successfully!', 'access_control')
            user_access = get_employee_access_control(user['name'])
            return redirect(url_for('controls'))


        if get_employee_controls:
            employee = request.form['employee']
            cursor.execute('SELECT * FROM access_control WHERE Employee_ID = ?', (employee,))
            row = cursor.fetchone()
            
            if row:
                # Map database row to dictionary
                employee_details = {
                    'Employee_ID': row[0], 
                    'accounts': row[1], 
                    'acc_expenses': row[2], 
                    'acc_clients': row[3], 
                    'acc_vendors': row[4], 
                    'profile': row[5], 
                    'prof_dashboard': row[6],
                    'prof_personal_details': row[7],
                    'prof_leaves': row[8], 
                    'prof_courses': row[9], 
                    'prof_pay_slip': row[10],
                    'prof_assets': row[11], 
                    'profile_Approvals_section': row[58], 
                    'profile_Payment_Req_approval': row[59], #------last one
                    'project': row[12], 
                    'proj_dashboard': row[13], 
                    'proj_project_summary': row[14], 
                    'proj_pr_po_project': row[15],
                    'proj_project_edit': row[16], 
                    'proj_timesheet': row[17], 
                    'proj_claims': row[18], 
                    'proj_enquiry': row[19], 
                    'proj_edit_enquiry': row[20], 
                    'proj_time_edit': row[21],
                    'proj_hours_view': row[22],
                    'proj_pr_po': row[36], 
                    'proj_pr_edit': row[37],
                    'proj_po_edit': row[38],
                    'proj_prj_request': row[57],
                    'pur_suppliers' : row[40],
                    'pur_purchaser' : row[39],
                    'pur_pr_approve' : row[41],
                    'pur_pr_process' : row[42],
                    'pur_pr_create' : row[43],
                    'pur_pr_edit' : row[44],
                    'pur_pr_delete' : row[45],
                    'pur_po_edit' : row[46],
                    'pur_po_print' : row[47],
                    'pur_po_delete' : row[48],
                    'pur_pr' : row[49],
                    'pur_po' : row[50],
                    'Material_Receipt' : row[51],
                    'DO_Delete' : row[52],
                    'purchase': row[23], 
                    'hr': row[24], 
                    'hr_add': row[25], 
                    'hr_course': row[26], 
                    'hr_leave': row[27], 
                    'hr_asset': row[28], 
                    'hr_option1': row[29],
                    'hr_leave_approvals': row[30], 
                    'hr_profile': row[31], 
                    'hr_update_bio': row[32], 
                    'hr_update_courses': row[33], 
                    'hr_update_assets': row[34], 
                    'hr_option2': row[35],
                    'hr_leave_Dashboard' : row[53],
                    'hr_leave_pending_Approval' : row[54],
                    'hr_leave_stats' : row[55],
                    'hr_leave_allocation' : row[56]
                }
            
            else:
                flash("Employee not found. Defaulting all values to 'Off'.")

                employee_details = {
                    'Employee_ID': employee,
                    'accounts': 'Off',
                    'acc_expenses': 'Off',
                    'acc_clients': 'Off',
                    'acc_vendors': 'Off',
                    'profile': 'Off',
                    'prof_dashboard': 'Off',
                    'prof_personal_details': 'Off',
                    'prof_leaves': 'Off',
                    'prof_courses': 'Off',
                    'prof_pay_slip': 'Off',
                    'prof_assets': 'Off',
                    'profile_Approvals_section': 'Off', 
                    'profile_Payment_Req_approval': 'Off', #------last one
                    'project': 'Off',
                    'proj_overview':'Off',
                    'proj_dashboard': 'Off',
                    'proj_project_summary': 'Off',
                    'proj_pr_po_project': 'Off',
                    'proj_project_edit': 'Off',
                    'proj_timesheet': 'Off',
                    'proj_claims': 'Off',
                    'proj_enquiry': 'Off',
                    'proj_edit_enquiry': 'Off',
                    'proj_time_edit': 'Off',
                    'proj_hours_view': 'Off',
                    'proj_pr_po': 'Off',
                    'proj_pr_edit': 'Off',
                    'proj_po_edit': 'Off',
                    'proj_prj_request': 'Off', 
                    'purchase': 'Off',
                    'pur_suppliers' : 'Off',
                    'pur_purchaser' : 'Off',
                    'pur_pr_approve' : 'Off',
                    'pur_pr_process' : 'Off',
                    'pur_pr_create' : 'Off',
                    'pur_pr_edit' : 'Off',
                    'pur_pr_delete' : 'Off',
                    'pur_po_edit' : 'Off',
                    'pur_po_print' : 'Off',
                    'pur_po_delete' : 'Off',
                    'pur_pr' : 'Off',
                    'pur_po' : 'Off',
                    'Material_Receipt' : 'Off',
                    'DO_Delete' : 'Off',
                    'hr': 'Off',
                    'hr_add': 'Off',
                    'hr_course': 'Off',
                    'hr_leave': 'Off',
                    'hr_asset': 'Off',
                    'hr_option1': 'Off',
                    'hr_leave_approvals': 'Off',
                    'hr_profile': 'Off',
                    'hr_update_bio': 'Off',
                    'hr_update_courses': 'Off',
                    'hr_update_assets': 'Off',
                    'hr_option2': 'Off',
                    'hr_leave_Dashboard' : 'Off',
                    'hr_leave_pending_Approval' : 'Off',
                    'hr_leave_stats' : 'Off',
                    'hr_leave_allocation' : 'Off' 
                }
            
            db.commit()
            user_access = get_employee_access_control(user['name'])

    
            return render_template('admin_templates/settings/controls.html', project_ids=project_ids,is_pm=is_pm, department_code=department_code, user=user, 
                           user_access=user_access,usernames=usernames,project_id=project_id,project_details=project_details,employee_details=employee_details)

    user_access = get_employee_access_control(user['name'])
    return render_template('admin_templates/settings/controls.html', project_ids=project_ids,is_pm=is_pm, department_code=department_code, user=user, 
                          user_access=user_access,employee_details=employee_details, usernames=usernames,project_id=project_id,project_details=project_details)

@app.route('/get_controls/<employee_id>', methods=['GET'])
def get_controls(employee_id):
    db = get_database()
    cursor = db.cursor()
    
    # Fetch employee control data from the access_control table
    query = """SELECT * FROM access_control WHERE Employee_ID = ?"""
    emp_controls = cursor.execute(query, (employee_id,)).fetchone()

    # If no controls found for the employee
    if not emp_controls:
        return jsonify({'success': False, 'message': "Couldn't find controls for the selected employee"})

    # Convert the tuple into a dictionary if needed
    control_keys = [description[0] for description in cursor.description]
    emp_controls_dict = dict(zip(control_keys, emp_controls))
    # print("......emp_controls_dict..........",emp_controls_dict)
    return jsonify({
        'success': True,
        'emp_controls': emp_controls_dict
    })

from flask import Flask, request, jsonify

def update_access_control(table_name):
    db = get_database()
    cursor = db.cursor()
    
    data = request.json
    employee_id = data.pop("Employee_ID", None)
    # print("..............data..........", data)
    
    if not employee_id:
        return jsonify({"success": False, "error": "Missing Employee_ID"})

    # Create query dynamically based on available keys
    columns = ', '.join(f"{key} = ?" for key in data.keys())
    values = list(data.values())

    query = f"""
        INSERT INTO {table_name} (Employee_ID, {', '.join(data.keys())}) 
        VALUES (?, {', '.join(['?'] * len(data))})
        ON CONFLICT(Employee_ID) DO UPDATE SET {columns};
    """
    try:
        cursor.execute(query, [employee_id] + values + values)
        db.commit()
        return jsonify({"success": True})
    except Exception as e:
        print("Error updating database:", e)
        return jsonify({"success": False, "error": str(e)})
    finally:
        db.commit()

@app.route('/update_leads_access_control', methods=['POST'])
def update_leads():
    return update_access_control("access_control")

@app.route('/update_accounts_access_control', methods=['POST'])
def update_accounts():
    return update_access_control("access_control")

@app.route('/update_hr_access_control', methods=['POST'])
def update_hr():
    return update_access_control("access_control")

@app.route('/update_profile_access_control', methods=['POST'])
def update_profile():
    return update_access_control("access_control")

@app.route('/update_Projects_access_control', methods=['POST'])
def update_projects():
    return update_access_control("access_control")

@app.route('/update_Purchase_access_control', methods=['POST'])
def update_purchase():
    return update_access_control("access_control")

@app.route('/update_Planner_access_control', methods=['POST'])
def update_planner():
    return update_access_control("access_control")

@app.route('/update_Resources_access_control', methods=['POST'])
def update_resources():
    return update_access_control("access_control")


#----------------------------------------------------------------------MAIN PROGRAM----------------------------------------------------------------
if __name__ =='__main__' :
    app.run(debug = True, host = "0.0.0.0", port = 5000)
    # webview.start()

# if __name__ == '__main__':
#     app.run(debug=True, port=5002)



