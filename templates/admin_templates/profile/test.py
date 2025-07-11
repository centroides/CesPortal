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

                department_code = get_department_code_by_username( user['name'])

                if department_code == 1025:
                    return redirect(url_for('accounts'))
                return redirect(url_for('projects'))
                pmstat  = get_pm_status(user['name'])
                pestat  = get_pe_status(user['name'])
                otp = generate_otp()
                store_otp_in_session(otp)
                if not existing_username:
                    return render_template('login.html', registererror='Your Email is not register with us .....!')
                else:
                    send_otp_email(user['email'], otp)
                    print("..........otp........",otp)
                    return render_template('verify_otp_page.html',mail = user['email'])
                # return render_template('admin_templates/admin/index.html')
                return redirect(url_for('projects'))
            else:
                error = "Username or Password did not match. Please try again."
        else:
            error = "Username or Password did not match. Please try again."
    username_suggestions = get_username_suggestions()
    return render_template('login.html', loginerror = error, user = user, username_suggestions = username_suggestions)

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

# def send_otp_email(receiver_email, otp):
#     # Connect to the Gmail SMTP server using SSL
#     s = smtplib.SMTP_SSL('smtp.gmail.com', 465)

#     # Login with the new email and password
#     s.login("da@centroides.com", "Sairam@123")

#     # Define email subject and body
#     subject = "From Centroid Engineering Solutions"
#     body = f"Your OTP is: '{otp}'. This OTP is valid for a short period. Do not share it with anyone."

#     # Create the email message
#     message = MIMEMultipart()
#     message['From'] = "da@centroides.com"
#     message['To'] = receiver_email
#     message['Subject'] = subject
#     message.attach(MIMEText(body, 'plain'))

#     # Send the email
#     s.sendmail("da@centroides.com", receiver_email, message.as_string())
#     print('OTP email sent successfully.')

#     # Close the connection
#     s.quit()

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
    return render_template('login.html', user=user)



from datetime import datetime, timedelta

def allowed_file(filename):
    allowed_extensions = {'txt', 'pdf', 'doc', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/view_file', methods=['GET'])
def view_file():
    file_folder = 'data'

    filename = request.args.get('filename')

    for root, dirs, files in os.walk(file_folder):
        for file in files:
            name, extension = os.path.splitext(file)
            if name == filename:
                file_path = os.path.join(root, file)
                try:
                    if os.path.exists(file_path):
                        return send_file(file_path)
                except Exception as e:
                    return str(e)

    return "File not found"

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

@app.route('/delete_enquiry', methods=['GET'])
def delete_enquiry():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    enquiry_number = request.args.get('enquiry_number')
    db = get_database()
    db.execute("DELETE FROM enquiries WHERE EnquiryNumber = ?", (enquiry_number,))
    db.commit()

    flash('Enquiry deleted successfully', 'success')
    return redirect(url_for('admin_enquiry'))

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

@app.route('/admin_employee_hours_edit/', methods=['GET', 'POST'])
def admin_employee_hours_edit():
    user = get_current_user()
    depart = get_department_code_by_username(user['name'])
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    current_year = datetime.now().year
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))
    usernames = [row[0] for row in cursor.fetchall()]
    data = []
    month_name = ''
    employee_id = ''
    current_date = datetime.now()
    start_day = current_date.replace(day=1).weekday()  # 0 for Monday, 1 for Tuesday, etc.
    last_day = calendar.monthrange(current_date.year, current_date.month)[1]
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        month = request.form.get('month')
        selectedMonth = month
        year = request.form.get('year')
        workingDate = f"{month} {year}"
        nyear = int(year)
        nmonth = int(month)
        month_name = calendar.month_name[nmonth]
        # cursor.execute('SELECT * FROM workingHours WHERE employeeID = ? AND substr(workingDate, 4) = ? AND section_code =?', (employee_id, workingDate,4000))
        cursor.execute('SELECT * FROM workingHours WHERE employeeID = ? AND substr(workingDate, 4) = ? AND section_code IN (4000, 5000)', (employee_id, workingDate))

        data = cursor.fetchall()

        # Calculate start_day and last_day for the current month
        current_date = datetime.now()
        start_day = current_date.replace(day=1).weekday()  # 0 for Monday, 1 for Tuesday, etc.
        last_day = calendar.monthrange(current_date.year, current_date.month)[1]

        # Group data by project
        project_hours = {}
        for entry in data:
            project_id = entry['projectID']
            working_date = entry['workingDate'][:2]
            hours_worked = entry['hoursWorked']

            if project_id not in project_hours:
                project_hours[project_id] = {'total_hours': 0, 'date_hours': {}}

            if working_date not in project_hours[project_id]['date_hours']:
                project_hours[project_id]['date_hours'][working_date] = hours_worked
            else:
                project_hours[project_id]['date_hours'][working_date] += hours_worked

            # Update total hours for the project
            project_hours[project_id]['total_hours'] += hours_worked

        # Organize the data for the template
        project_data = []
        for project_id, project_info in project_hours.items():
            project_data.append({
                'projectID': project_id,
                'total_hours': project_info['total_hours'],
                'date_hours': project_info['date_hours'],
            })

        print(project_data)

        return render_template("admin_templates/projects/admin_employee_hours_edit.html", user=user,department_code=department_code, usernames=usernames, selected_month=month_name, employee_id=employee_id,
                           is_pm=is_pm,current_year=current_year, data=project_data, start_day=start_day, last_day=last_day,selectedMonth=selectedMonth)

    return render_template("admin_templates/projects/admin_employee_hours_edit.html",is_pm=is_pm, user=user, usernames=usernames,department_code=department_code, current_year=current_year, data=data, start_day=start_day, last_day=last_day)

from datetime import datetime
@app.route('/save_all_hours', methods=['POST'])
def save_all_hours():
    if request.method == 'POST':
        user = get_current_user()
        entries = request.json.get('entries')
        selected_month = request.json.get('selectedMonth')
        selected_year = request.json.get('selectedYear')
        db = get_database()
        cursor = db.cursor()
        print(request.json)
        for entry in entries:
            project_id = entry['projectID']  # Use projectID
            # print("...........project_id",project_id)
            hours_worked = int(entry['hoursWorked'])
            # print(".......hours_worked",hours_worked)
            formatted_day = entry['workingDate'].split(' ')[0]
            # Construct the working_date in the format 'DD MM YYYY'
            working_date = f"{formatted_day} {selected_month} {selected_year}"
            # print("..............working_date",working_date)

            # Update the workingDate in the table
            cursor.execute('UPDATE workingHours SET hoursWorked = ? WHERE projectID = ? AND workingDate = ?', (hours_worked, project_id, working_date))

        db.commit()
        flash('Hours updated successfully', 'success')

        current_year = datetime.now().year
        start_day = 1  # Replace with your actual value

        placeholders = ', '.join(['?'] * len(entries))
        query = 'SELECT * FROM workingHours WHERE projectID IN ({})'.format(placeholders)
        updated_data = cursor.execute(query, [entry['projectID'] for entry in entries]).fetchall()

        return render_template('admin_templates/projects/admin_employee_hours_edit.html',user=user, updated_data=updated_data, current_year=current_year, start_day=start_day)

    return render_template('admin_templates/projects/admin_employee_hours_edit.html',user=user, updated_data=updated_data)

@app.route('/admin_time_sheet',methods=['GET', 'POST'])
@login_required
def admin_time_sheet():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        project_id = request.form['project_id']
        # print(".....................",project_id)
        # print("Type of project_id:", type(project_id))
        client = request.form['client']
        project_name = request.form['project_name']
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').strftime('%d %m %Y')
        hours_worked = request.form['hours_worked']
        department_code = request.form['department_code']


        # Check if a row with the same key exists in temp_workingHours
        existing_row = db.execute(
            'SELECT hoursWorked FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?',
            (project_id, department_code, employee_id, date)).fetchone()

        project_status = check_project_status(project_id)
        if project_status == 'Closed':
            flash('Project is closed. Please Contact Administrator.....!', 'error')
        if project_status == 'Select':
            flash('Project is not opened yet, Please Contact Administrator.....!', 'error')
        elif existing_row:
            # If the row exists, update the hoursWorked by adding the new value to the existing value
            existing_hours = float(existing_row[0])
            new_hours = existing_hours + float(hours_worked)
            if new_hours > 24:
                flash(' working cannot exceed 24 hours.', 'error')
            else:
                db.execute(
                    'UPDATE temp_workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?',
                    (new_hours, project_id, department_code, employee_id, date))
        else:
            # If the row doesn't exist, insert a new row
            if float(hours_worked) > 24:
                flash('Hours worked cannot exceed 24 hours.', 'error')
            else:
                db.execute(
                    'INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (project_id, department_code, employee_id, project_name, client, date, hours_worked))

        pro_cur = db.execute('SELECT projectID, departmentID, employeeID, project_name, client,workingDate, hoursWorked FROM temp_workingHours where projectID  =?', (project_id,))

        # print("...................................................",pro_cur)
        allpro = []
        for pro_row in pro_cur.fetchall():
            pro_dict = dict(pro_row)
            allpro.append(pro_dict)

        workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
        workingHours_allpro = []
        for pro_row in workingHours_pro_cur.fetchall():
            pro_dict = dict(pro_row)
            workingHours_allpro.append(pro_dict)

        username = user['name']
        department_code = get_department_code_by_username(username)
        client_suggestions = get_client_names()
        tempclientname = request.form.get('temp_client_name')
        project_id_suggestions = get_project_ids_by_client(tempclientname)
        project_names_suggestions = get_project_names()
        current_date = datetime.now().date()
        min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')

        db.commit()
        return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,
                               department_code=department_code,usernames=usernames,
                               client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,
                               workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                               allpro=allpro)
    temp=1
    pro_cur = db.execute('SELECT projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked FROM temp_workingHours')
    allpro = []
    for pro_row in pro_cur.fetchall():
        pro_dict = dict(pro_row)
        allpro.append(pro_dict)

    workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
    workingHours_allpro = []
    for pro_row in workingHours_pro_cur.fetchall():
        pro_dict = dict(pro_row)
        workingHours_allpro.append(pro_dict)

    username = user['name']
    department_code = get_department_code_by_username(username)
    client_suggestions = get_client_names()
    tempclientname = request.form.get('temp_client_name')
    project_id_suggestions = get_project_ids_by_client(tempclientname)
    project_names_suggestions = get_project_names()
    current_date = datetime.now().date()
    min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')

    return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,
                           department_code=department_code,usernames=usernames,
                           client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,
                           project_names_suggestions=project_names_suggestions, allpro=allpro,
                           workingHours_allpro=workingHours_allpro)

@app.route('/log', methods=['POST'])
def log():
    data = request.get_json()
    print("Received data:", data)
    return jsonify({"message": "Log data received"})

def generate_date_range(start_date, end_date):
    start_date = datetime.strptime(start_date, "%d %m %Y")
    end_date = datetime.strptime(end_date, "%d %m %Y")
    date_range = [start_date + timedelta(days=x) for x in range((end_date - start_date).days + 1)]
    return date_range

@app.route('/temp_employee', methods=['GET', 'POST'])
@login_required
def temp_employee():
    user = get_current_user()
    db = get_database()
    if 'confirm' in request.form:
        data = request.form.getlist('data[]')
        selected_projects = request.form.getlist('selected_projects[]')  # Get selected checkboxes
        # print("....................selected_projects.....................", selected_projects)
        # print("Received data:", data)
        for item in data:
            projectID, client, project_name, workingDate, hoursWorked, employeeID, departmentID = item.split('|')
            if f"{projectID},{employeeID}" in selected_projects:  # Check if this row is selected
                # print(",,,,,,,,,,,,,,,,,,inside the if condition.....................", projectID,".......................",employeeID)
                existing_row = db.execute(
                    "SELECT hoursWorked FROM workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?",
                    (projectID, departmentID, employeeID, workingDate)).fetchone()

                if existing_row:
                    existing_hours = existing_row[0]
                    new_hours = float(existing_hours) + float(hoursWorked)
                    db.execute(
                        "UPDATE workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?",
                        (new_hours, projectID, departmentID, employeeID, workingDate))
                else:
                    db.execute(
                        "INSERT INTO workingHours (projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, client) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, client))

                db.execute("DELETE FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?",
                    (projectID, departmentID, employeeID, workingDate))
    elif 'delete' in request.form:

        data = request.form.getlist('data[]')
        selected_projects = request.form.getlist('selected_projects[]')  # Get selected checkboxes
        # print("....................selected_projects.....................", selected_projects)
        # print("Received data:", data)
        for item in data:
            projectID, client, project_name, workingDate, hoursWorked, employeeID, departmentID = item.split('|')
            if f"{projectID},{employeeID}" in selected_projects:  # Check if this row is selected
                db.execute("DELETE FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?",
                    (projectID, departmentID, employeeID, workingDate))

        db.commit()

    user = get_current_user()
    username = user['name']
    employee_id_to_filter = user['name']  # Replace with the specific employee ID you want to filter by
    query = '''SELECT projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked FROM temp_workingHours WHERE employeeID = ?'''
    pro_cur = db.execute(query, (employee_id_to_filter,))
    allpro = []
    for pro_row in pro_cur.fetchall():
        pro_dict = dict(pro_row)
        allpro.append(pro_dict)

    current_date = datetime.now().date()
    date_range = [current_date - timedelta(days=i) for i in range(15)]
    # Query the database for the total hours worked on each date
    workingHours_allpro = []
    for date in date_range:
        # print("................",date)
        formatted_date = date.strftime('%d-%m-%y')
        total_hours = 0
        # Query the database for the total hours worked on the current date
        rows = db.execute('''SELECT SUM(hoursWorked) as totalHours FROM workingHours WHERE employeeID = ? AND workingDate = ?''', (user['name'], formatted_date)).fetchone()
        if rows and rows['totalHours'] is not None:
            total_hours = rows['totalHours']
        workingHours_allpro.append({'workingDate': formatted_date, 'totalHours': total_hours})

    workingHours_allpro = workingHours_allpro[::-1]
    workingHours_allpro.reverse()
    username = user['name']
    department_code = get_department_code_by_username(username)
    pm_status = get_pm_status(username)
    client_suggestions = get_client_names()
    tempclientname = request.form.get('temp_client_name')
    project_id_suggestions = get_project_ids_by_client(tempclientname)
    project_names_suggestions = get_project_names()
    current_date = datetime.now().date()
    min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')

    return render_template('employee.html', user=user, current_date=current_date, min_date=min_date, pm_status=pm_status, department_code=department_code,
                        client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,
                        project_names_suggestions=project_names_suggestions, allpro=allpro,
                        workingHours_allpro=workingHours_allpro)  # Pass total_hours here

@app.route('/final_employee', methods=['GET', 'POST'])
@login_required
def final_employee():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    if request.method == 'POST':
        employee_id = user['name']
        project_id = request.form['project_id']
        client = request.form['client']
        project_name = request.form['project_name']
        date = request.form['date']
        hours_worked = request.form['hours_worked']
        department_code = get_department_code_by_username(user['name'])
        db.execute('INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked) VALUES (?, ?, ?, ?, ?, ?, ?)',[project_id, department_code, employee_id, project_name, client, date, hours_worked])
        db.commit()
        return redirect(url_for('employee'))


    username = user['name']
    department_code = get_department_code_by_username(username)
    pm_status = get_pm_status(username)
    client_suggestions = get_client_names()
    tempclientname = request.form.get('temp_client_name')  # Retrieve the selected client name
    # print("-------------------------------------...........................................................",tempclientname)
    project_id_suggestions = get_project_ids_by_client(tempclientname)
    project_names_suggestions = get_project_names()
    # current_date = datetime.datetime.now().date()
    current_date = datetime.now().date()  # If you used `from datetime import datetime`
    min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')

    return render_template('employee.html', user=user, current_date = current_date, min_date =min_date, pm_status=pm_status, department_code=department_code,client_suggestions=client_suggestions,project_id_suggestions=project_id_suggestions, project_names_suggestions = project_names_suggestions)

@app.route('/home')
def home():
    user = get_current_user()
    return render_template('home.html', user=user)

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
    session.clear()
    session.pop('user', None)
    return redirect(url_for('login'))
    # render_template('/home.html')

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
        cursor.execute("SELECT id FROM projects WHERE client = ?", (client,))
        project_ids = [row[0] for row in cursor.fetchall()]
        return jsonify(project_ids=project_ids)
    except Exception as e:
        return jsonify(project_ids=[]), 500  # Return an empty list and a 500 status code for error
    finally:
        cursor.close()
        db.close()


####-----------------------------------------------profile---------------------------------------------------------------------------------------------------------

@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    EmployeeID = user['name']

    # Fetch attended courses for the employee
    cursor.execute("SELECT * FROM attended_courses WHERE Employee_ID = ?", (EmployeeID,))
    courses_data = cursor.fetchall()

    from datetime import datetime, timedelta
    courses = []

    for row in courses_data:
        course = {
            "ID": row[0],
            "Name": row[1],
            "Course_Name": row[2],
            "Date_Attained": row[3],
            "Expiry_Date": row[4]
        }

        date_attained = datetime.strptime(course['Date_Attained'], "%Y-%m-%d")
        expiry_date = datetime.strptime(course['Expiry_Date'], "%Y-%m-%d")
        days_left = (expiry_date - datetime.now()).days
        course['Days_Left'] = days_left

        courses.append(course)

    print("............courses..................",courses)

    # Fetch issued assets for the employee
    cursor.execute("SELECT * FROM issued_assets WHERE Employee_ID = ?", (EmployeeID,))
    assets = cursor.fetchall()

    leave_types = ['Madical', 'Casual', 'Annual', 'Maternity', 'Paternity']
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
        used_dict['Madical'] = used_dict.pop('Medical')

    table_rows = []
    for leave_type in eligibility_dict:
        eligibility = eligibility_dict.get(leave_type, 0)
        used = used_dict.get(leave_type, 0)
        left = eligibility - used
        table_rows.append((leave_type, eligibility, used, left))
    table_rows = [(leave_type.replace('Madical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]

    from datetime import datetime, timedelta

    one_month_ago = datetime.now() - timedelta(days=30)
    cursor.execute("""SELECT section_code, projectID, hoursWorked, formatted_date FROM workingHours WHERE employeeID = ? AND formatted_date >= ?""",  (user['name'], one_month_ago.strftime('%Y-%m-%d')))

    results = cursor.fetchall()
    data = []
    for row in results:
        entry = { 'section_code': row[0], 'projectID': row[1], 'hoursWorked': row[2], 'formatted_date': row[3] }
        data.append(entry)

    if not data:
        return render_template('admin_templates/profile/profile.html', dates=[], pro_ids=[], hours_spent=[], hours=[], table_rows=table_rows, user=user, department_code=department_code)

    df = pd.DataFrame(data)
    # Convert 'formatted_date' to datetime
    df['formatted_date'] = pd.to_datetime(df['formatted_date'])
    df['formatted_date'] = df['formatted_date'].dt.strftime('%d-%m-%y')
    # Group by 'formatted_date' and sum the 'hoursWorked'
    df_date_hours = df.groupby('formatted_date')['hoursWorked'].sum().reset_index()
    # Extract the lists
    dates = df_date_hours['formatted_date'].tolist()
    hours = df_date_hours['hoursWorked'].tolist()
    df_project_hours = df.groupby('projectID')['hoursWorked'].sum().reset_index()
    pro_ids = df_project_hours['projectID'].tolist()
    hours_spent = df_project_hours['hoursWorked'].tolist()



    employee_id = user['name']
    cursor = db.execute('''SELECT id, Full_Employee_ID, display_Name, Designation, Expense_Code, Email_Id, Race, Sector, Date_Joined, Date_Left, Employee_Status, UserName_Portal, Password_Portal, Nationality,
                                Pass_Type, NRIC, FIN, WP, Passport_No, Passport_Exp_Date, DOB, Phone_No, Personal_Mail, Address, Emergency_Contact, Emergency_Contact_Address, Relation_to_Employee,
                                Basic, Employee_cpf, Employer_cpf, Allowance_Housing, Allowance_Transport, Allowance_Phone, Allowance_Others, Fund_CDAC, Fund_ECF, Fund_MBMF, Fund_SINDA,
                                Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Pass_Exp_Date
                        FROM employee_details
                        WHERE display_Name = ?''', (employee_id,))

    emp_data = cursor.fetchone()




    total_projects = db.execute("SELECT COUNT(DISTINCT projectID) AS projects_involved FROM workingHours WHERE employeeID = ?;", (employee_id,)).fetchone()[0]
    total_hours_worked = db.execute("SELECT SUM(hoursWorked) FROM workingHours WHERE employeeID = ?", (employee_id,)).fetchone()[0]
    total_leaves = db.execute("SELECT COUNT(*) FROM leaves WHERE employeeID = ?", (employee_id,)).fetchone()[0]
    total_courses_attended = db.execute("SELECT COUNT(*) FROM attended_courses WHERE Employee_ID = ?", (employee_id,)).fetchone()[0]
    total_assets_issued = db.execute("SELECT COUNT(*) FROM issued_assets WHERE Employee_ID = ?", (employee_id,)).fetchone()[0]
    total_claims = db.execute("SELECT COUNT(*), SUM(claim_Total) FROM claims WHERE claim_by = ?", (employee_id,)).fetchone()
    total_enquiries = db.execute("SELECT COUNT(*) FROM enquiries WHERE client = ?", (employee_id,)).fetchone()[0]

    # Data for charts
    hours_worked_data = db.execute("SELECT workingDate, SUM(hoursWorked) FROM workingHours WHERE employeeID = ? GROUP BY workingDate", (employee_id,)).fetchall()
    leave_types_data = db.execute("SELECT leave_type, COUNT(*) FROM leaves WHERE employeeID = ? GROUP BY leave_type", (employee_id,)).fetchall()
    claims_status_data = db.execute("SELECT status, COUNT(*) FROM claims WHERE claim_by = ? GROUP BY status", (employee_id,)).fetchall()
    expenses_data = db.execute("SELECT claim_date, SUM(claim_Total) FROM Expenses WHERE claim_by = ? GROUP BY claim_date", (employee_id,)).fetchall()
    course_expiry_data = db.execute("SELECT Course_Name, Expiry_Date FROM attended_courses WHERE Employee_ID = ?", (employee_id,)).fetchall()

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




    return render_template('admin_templates/profile/profile.html', dates=dates, pro_ids=pro_ids, hours_spent=hours_spent, hours=hours, table_rows=table_rows, user=user, department_code=department_code,
                           total_projects=total_projects, total_hours_worked=total_hours_worked, total_leaves=total_leaves, total_courses_attended=total_courses_attended,
                           total_assets_issued=total_assets_issued, total_claims=total_claims[0], claim_total=total_claims[1], total_enquiries=total_enquiries, hours_worked=hours_worked,
                           work_dates=work_dates, leave_types=leave_types, leave_counts=leave_counts, claim_statuses=claim_statuses, claim_counts=claim_counts, expense_dates=expense_dates, expense_amounts=expense_amounts,
                           course_names=course_names, course_expiry_dates=course_expiry_dates,emp_data=emp_data,courses=courses,assets=assets)





####-----------------------------------------------HR---------------------------------------------------------------------------------------------------------

@app.route('/hr')
def hr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM leaves_yet_to_approve WHERE status = 'Pending'")
    pending_leaves_count = cursor.fetchone()[0]
    department_code = get_department_code_by_username( user['name'])
    db.commit()
    return render_template('admin_templates/hr/hr_main_page.html',user=user,is_pm=is_pm,department_code=department_code,pending_leaves_count=pending_leaves_count)

@app.route('/leave_approvals', methods=['GET', 'POST'])
def leave_approvals(leave_id=None):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
    leaves_yet_to_approve = cursor.fetchall()
    cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
    approved_leaves = cursor.fetchall()
    table_rows = []
    leave_details = []
    approved_date = datetime.now().strftime('%Y-%m-%d')

    if request.method == 'POST':
        leave_id = request.form.get('leave_id')
        row_id = request.form.get('row_id')
        delleaverow = request.form.get('delleaverow')
        cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE id = ?', (leave_id,))
        leave_details = cursor.fetchone()

        if row_id:

            cursor = cursor.execute('SELECT * FROM leaves WHERE temp_id =?  ORDER BY id DESC',(row_id,))
            leave_rows = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
            leaves_yet_to_approve = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()
            db.commit()
            leave_details = [ ]
            return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves, leave_rows=leave_rows,row_id=row_id,
                        department_code=department_code,leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)

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
            cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
            leaves_yet_to_approve = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()
            db.commit()
            leave_details = [ ]
            return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves, leave_rows=leave_rows,row_id=row_id,
                        department_code=department_code,leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)

        if leave_details:
            EmployeeID = leave_details['employeeID']
            leave_types = ['Madical', 'Casual', 'Annual', 'Maternity', 'Paternity']
            # Initialize eligibility_dict with leave types and zero values
            eligibility_dict = {leave_type: 0 for leave_type in leave_types}
            # Retrieve data from the database
            cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
            employee_leave_eligibility_data = cursor.fetchall()

            # Update eligibility_dict based on the retrieved data
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
                used_dict['Madical'] = used_dict.pop('Medical')
            table_rows = []
            # Iterate through leave types and populate the table
            for leave_type in eligibility_dict:
                eligibility = eligibility_dict.get(leave_type, 0)
                used = used_dict.get(leave_type, 0)
                left = eligibility - used
                # Append a tuple representing a table row
                table_rows.append((leave_type, eligibility, used, left))
            table_rows = [(leave_type.replace('Madical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]

            cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
            leaves_yet_to_approve = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
            approved_leaves = cursor.fetchall()

            return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,EmployeeID=EmployeeID,user=user,department_code=department_code,
                                  approved_leaves=approved_leaves, leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)

        if 'Approve' in request.form:
            id1 = request.form.get('id1')
            print("...........id1........",id1)

            if id1:
                current_user = get_current_user()
                db = get_database()
                cursor = db.cursor()
                from datetime import timedelta
                from dateutil import parser
                # Fetch and parse public holidays
                public_holidays = set()
                cursor.execute('SELECT date FROM public_holidays')
                public_holidays_data = cursor.fetchall()
                for holiday in public_holidays_data:
                    public_holidays.add(parser.parse(holiday['date']).date())

                # Update leave status
                cursor.execute('UPDATE leaves_yet_to_approve SET status=? WHERE id=?', ('Approved', id1))
                cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE id=?', (id1,))
                leave_details = cursor.fetchone()
                approved_date = datetime.now().date()

                # Insert into leaves_approved table
                cursor.execute('INSERT INTO leaves_approved (employeeID, section_code, leave_type, start_date, end_date, number_of_days, department_code, status, approved_by, approved_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (leave_details['employeeID'], leave_details['section_code'], leave_details['leave_type'], leave_details['start_date'], leave_details['end_date'], leave_details['number_of_days'], leave_details['department_code'], 'Approved', current_user['name'], approved_date))

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

                cursor.execute('SELECT MAX(id) FROM leaves_approved')
                latest_id = cursor.fetchone()[0]

                while current_date <= end_date1:
                    if current_date.weekday() not in (5, 6) and current_date not in public_holidays:
                        cursor.execute(
                            'INSERT INTO leaves (employeeID, section_code, leave_type, leave_date, leave_duration, department_code, status, approved_by, approved_date,temp_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)',
                            (leave_details['employeeID'], leave_details['section_code'], leave_details['leave_type'], current_date.strftime('%Y-%m-%d'), number_of_days, department_code, 'Approved', current_user['name'], approved_date,latest_id))
                    current_date += timedelta(days=1)

                # Fetch data for rendering the template
                cursor = cursor.execute('SELECT * FROM leaves_approved ORDER BY id DESC')
                approved_leaves = cursor.fetchall()
                cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
                leaves_yet_to_approve = cursor.fetchall()
                current_user = current_user['name']
                user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', [leave_details['employeeID']])
                mail_to_row = user_cur.fetchone()

                # Ensure that an email was found for the user
                if mail_to_row:
                    mail_to = mail_to_row['name']
                    print(".......mail_to............", mail_to)

                    # Sending the leave notification email
                    send_leaves_notification(mail_to, leave_details)
                else:
                    print(f"No email found for user: {leave_details['employeeID']}")

                db.commit()

                leave_details = []
                user = get_current_user()
                department_code = get_department_code_by_username(user['name'])

                return render_template('admin_templates/hr/leave_approvals.html', leave_details=leave_details, user=user, approved_leaves=approved_leaves,
                                    department_code=department_code, leaves_yet_to_approve=leaves_yet_to_approve)
            else:
                db.commit()
                return render_template('admin_templates/hr/leave_approvals.html', leave_details=[], user=get_current_user(), approved_leaves=[], department_code=get_department_code_by_username(get_current_user()['name']), leaves_yet_to_approve=[])

        if 'Reject' in request.form:
            id1 = request.form.get('id1')
            if id1:
                current_user = get_current_user()
                db = get_database()
                cursor = db.cursor()
                cursor.execute('UPDATE leaves_yet_to_approve SET status=? WHERE id=?',('Rejected', id1))
                cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE id=?', (id1,))
                leave_details = cursor.fetchone()
                cursor.execute('INSERT INTO leaves_approved (employeeID, section_code, leave_type, start_date, end_date, number_of_days, department_code, status, approved_by, approved_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (leave_details['employeeID'], leave_details['section_code'], leave_details['leave_type'], leave_details['start_date'], leave_details['end_date'], leave_details['number_of_days'], leave_details['department_code'], 'Rejected', current_user['name'], approved_date))
                cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
                approved_leaves = cursor.fetchall()
                cursor = cursor.execute('SELECT * FROM leaves_yet_to_approve WHERE status = ? ORDER BY id DESC', ('Pending',))
                leaves_yet_to_approve = cursor.fetchall()
                cursor = cursor.execute('SELECT * FROM leaves_approved  ORDER BY id DESC')
                approved_leaves = cursor.fetchall()
                user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', [leave_details['employeeID']])
                mail_to_row = user_cur.fetchone()

                # Ensure that an email was found for the user
                if mail_to_row:
                    mail_to = mail_to_row['name']
                    print(".......mail_to............", mail_to)
                    # Sending the leave notification email
                    send_leaves_notification(mail_to, leave_details)
                else:
                    print(f"No email found for user: {leave_details['employeeID']}")
                db.commit()
                leave_details = [ ]
                return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves,
                            department_code=department_code,leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)
            return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves,
                           department_code=department_code,leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)

    db.commit()

    return render_template('admin_templates/hr/leave_approvals.html',leave_details=leave_details,user=user,approved_leaves=approved_leaves,
                           department_code=department_code,leaves_yet_to_approve=leaves_yet_to_approve,table_rows=table_rows)

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
    leave_types = ['Madical', 'Casual', 'Annual', 'Maternity', 'Paternity']
    # Initialize eligibility_dict with leave types and zero values
    eligibility_dict = {leave_type: 0 for leave_type in leave_types}
    # Retrieve data from the database
    cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
    employee_leave_eligibility_data = cursor.fetchall()

    # Update eligibility_dict based on the retrieved data
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
        used_dict['Madical'] = used_dict.pop('Medical')
    table_rows = []
    # Iterate through leave types and populate the table
    for leave_type in eligibility_dict:
        eligibility = eligibility_dict.get(leave_type, 0)
        used = used_dict.get(leave_type, 0)
        left = eligibility - used
        # Append a tuple representing a table row
        table_rows.append((leave_type, eligibility, used, left))
    table_rows = [(leave_type.replace('Madical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]

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

        if Delete:
            db.execute("DELETE FROM courses WHERE id = ?", (Delete,))
            db.commit()
            option = 'courses'
        if Delete_Asset:
            db.execute("DELETE FROM assets WHERE id = ?", (Delete_Asset,))
            db.commit()
            option = 'asset'
        if Delete_Leave:
            db.execute("DELETE FROM admin_leave_allocation WHERE id = ?", (Delete_Leave,))
            db.commit()
            option = 'leave'


        if form_type == 'course':
            Course_Name = request.form['Course_Name']
            db.execute("INSERT INTO courses (Course_Name) VALUES (?)", (Course_Name,))
            db.commit()
            option = 'courses'


        elif form_type == 'asset':
            Asset_Name = request.form['Asset_Name']
            Model = request.form['Model']
            S_N = request.form['S_N']
            db.execute("INSERT INTO assets (Asset_Name, Model, S_N, status) VALUES (?, ?, ?, ?)", (Asset_Name, Model, S_N, 'Open'))
            db.commit()
            option = 'asset'

        elif form_type == 'leave':
            EmployeeID = request.form['employee_id']
            Madical = request.form['Madical']
            Casual = request.form['Casual']
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
                update_query = ''' UPDATE admin_leave_allocation SET Madical = ?, Casual = ?, Annual = ?, Maternity = ?, Paternity = ?, Public=? WHERE EmployeeID = ?'''
                db.execute(update_query, (Madical, Casual, Annual, Maternity, Paternity,holiday_count, EmployeeID))
                cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
            else:
                # EmployeeID does not exist, insert a new row
                insert_query = '''INSERT INTO admin_leave_allocation (EmployeeID, Madical, Casual, Annual, Maternity, Paternity, Public) VALUES (?, ?, ?, ?, ?, ?, ?)'''
                db.execute(insert_query, (EmployeeID, Madical, Casual, Annual, Maternity, Paternity, holiday_count))
                cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
            db.commit()
            option = 'leave'


    cursor = db.execute('SELECT * FROM admin_leave_allocation ORDER BY id DESC')
    leaves_data = cursor.fetchall()
    cursor = db.execute('SELECT * FROM courses ORDER BY id DESC')
    courses = cursor.fetchall()
    cursor = db.execute('SELECT * FROM assets ORDER BY id DESC')
    assets = cursor.fetchall()

    return render_template('admin_templates/hr/hr_add.html',is_pm=is_pm,department_code=department_code, user=user, table_rows=table_rows, leaves=leaves, assets=assets,
                          leaves_data=leaves_data, option=option, courses=courses, usernames=usernames)

@app.route('/hr_employee_bio', methods=['GET', 'POST'])
def hr_employee_bio():

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()

    # Q1 = """SELECT username, department_code FROM admin_user"""
    # user_data1 = db.execute(Q1).fetchall()
    # user_data = sorted(user_data1, key=lambda x: x[0].lower())

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
                                    Deduction_Housing, Deduction_Transport, Deduction_Phone, Deduction_Others, Levy, SDL, Total, Rate_hr, Rate_day, Annual_Leave, Pass_Exp_Date, Date_of_Application, Pass_Exp_Date
                            FROM employee_details
                            WHERE display_Name = ?''', (employee_id,))

        emp_data = cursor.fetchone()

    if request.method == 'POST':
        form_type = request.form.get('form_type')
        print("form_type...................",form_type)

        if form_type == 'bio_form':
            # Extract data from the form
            display_Name = request.form.get('display_Name')
            print("................display_Name...................", display_Name)
            print("................display_Name length...................", len(display_Name))
            Semp_code = get_department_code_by_username(display_Name)
            Full_Employee_ID = request.form.get('Full_Employee_ID')
            designation = request.form.get('Designation')
            Expense_Code = request.form.get('Expense_Code')
            print(".............Expense_Code....",Expense_Code)
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
            wp = request.form.get('WP')
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
            print(".............Semp.........",Semp)
            print(".............Semp_code.........",Semp_code)

        elif form_type == 'update_courses':
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

        elif form_type == 'update_assets':
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

        elif form_type == 'add_courses':
            employee_id = request.form.get('employee_id17')
            course_name = request.form.get('selected_course')
            date_attained = request.form.get('Date_Attained')
            expiry_date = request.form.get('Expiry_Date')
            Semp_code = get_department_code_by_username(employee_id)


            if employee_id and course_name and date_attained and expiry_date:
                # Check if the employee has already attained the course
                cursor.execute("SELECT * FROM attended_courses WHERE Employee_ID = ? AND Course_Name = ?", (employee_id, course_name))
                existing_course = cursor.fetchone()

                if existing_course:
                    flash('Employee has already attained this course.', 'hr_employee_add_course_error')
                else:
                    # Insert the new course data
                    cursor.execute("INSERT INTO attended_courses (Employee_ID, Course_Name, Date_Attained, Expiry_Date) VALUES (?, ?, ?, ?)",
                                (employee_id, course_name, date_attained, expiry_date))
                    flash('Course added successfully!', 'hr_employee_add_course_error')
            else:
                flash('All fields are required.', 'hr_employee_add_course_error')

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

        elif form_type == 'add_asset':
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
    db.commit()

    return render_template('admin_templates/hr/hr_employee_bio.html',assect_dict = assect_dict, Semp=Semp,courses_dict=courses_dict, usernames=usernames,is_pm=is_pm,department_code=department_code,
                          Semp_code=Semp_code,all_courses=all_courses,asset_names=asset_names,emp_data=emp_data,user_data=user_data,content=content, option=option,user=user)

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
    print("......employee_id.......",employee_id)
    if employee_id:
        print("......employee_id.......",employee_id)
        # Query the database for employee details
        db = get_database()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM employee_details WHERE Employee_ID = ?", (employee_id,))
        employee = cursor.fetchone()
        db.close()

        if employee:
            employee_dict = dict(employee)
            print("......employee_dict.......",employee_dict)
            return jsonify(employee_dict)
        else:
            return jsonify({'error': 'Employee not found'})

    return jsonify({'error': 'Invalid request'})

@app.route('/delleave/<int:id>', methods=["GET", "POST"])
@login_required
def delleave(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()

        # Delete from leaves_approved where id matches
        cursor.execute('DELETE FROM leaves_approved WHERE id = ?', [id])

        # Delete from leaves where temp_id matches
        cursor.execute('DELETE FROM leaves WHERE temp_id = ?', [id])

        db.commit()
        return redirect(url_for('leave_approvals'))

    return render_template('leave_approvals.html', user=user)

##----------------------------------------------------ACCOUNTS------------------------------------------------------------------------------------------------------------

def get_claim_details():

    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT claim_id, claim_by, approved_date, claim_Total FROM claims")
    claim_details = cursor.fetchall()
    all_claim_details = []
    for row in claim_details:
        claim_detail = {'claim_id': row[0], 'claim_by': row[1],'approved_date': row[2],'claim_Total': row[3]}
        all_claim_details.append(claim_detail)
    return all_claim_details


@app.route('/accounts')
def accounts():

    if not session.get('logged_in'):
        return redirect(url_for('login'))
    import datetime  # Ensure you import the datetime module

    user = get_current_user()
    user_name = user['name']
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username( user['name'])
    return render_template('admin_templates/accounts/accounts_main_page.html',user=user,department_code=department_code)

@app.route('/view_claim/<claim_no>')
def view_claim(claim_no):
    pdf_file_path = f'claims/{claim_no}.pdf'
    if not os.path.isfile(pdf_file_path):
        return "Claim PDF not found."
    # Open and serve the PDF content in the iframe
    with open(pdf_file_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        return Response(pdf_content, content_type='application/pdf')

@app.route('/non_po_approvals',methods=['GET', 'POST'])
@login_required
def non_po_approvals():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    active_tab = 'dashboard'
    db = get_database()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    all_claim_details = get_claim_details()

    return render_template('admin_templates/accounts/non_po_approvals.html',is_pm=is_pm,department_code=department_code,
                           all_claim_details=all_claim_details, user=user,active_tab=active_tab)

@app.route('/po_approvals',methods=['GET', 'POST'])
@login_required
def po_approvals():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    active_tab = 'dashboard'
    db = get_database()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    all_claim_details = get_claim_details()

    return render_template('admin_templates/accounts/po_approvals.html',is_pm=is_pm,department_code=department_code,
                           all_claim_details=all_claim_details, user=user,active_tab=active_tab)

@app.route('/generate_gst',methods=['GET', 'POST'])
@login_required
def generate_gst():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    return render_template('admin_templates/accounts/generate_gst.html',is_pm=is_pm,department_code=department_code,user=user)



@app.route('/Expenses',methods=['GET', 'POST'])
@login_required
def Expenses():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor = db.cursor()
    cursor.execute('SELECT id FROM projects ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT * FROM temp_expences WHERE claim_by = ?', (user['name'],))
    claims_data = cursor.fetchall()
    cursor.execute('SELECT DISTINCT itemname FROM expences_items')
    itemname_suggestions = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT display_name FROM vendors_details')
    vendor_suggestions = [row[0] for row in cursor.fetchall()]
    existed_claim = None
    cursor.execute('SELECT SUM(total) FROM temp_expences WHERE claim_by = ?', (user['name'],))
    total_sum = cursor.fetchone()[0]  # Fetch the total sum value

    # Round the total sum to 2 decimal places
    if total_sum  is not None:
        rounded_total_sum = round(total_sum, 2)
    else:
        rounded_total_sum = 0

    if request.method == 'POST':
        username = user['name']
        date = request.form['date']
        projectid = request.form.get('projectid', '')
        project_name = request.form.get('project_name', '')
        if not projectid and not project_name:
            projectid = request.form.get('enqid', '')
            project_name = request.form.get('enq_name', '')

        vendor = request.form['vendor']
        Category = request.form['project']
        Sub_Category = request.form.get('Sub_Category', '')
        Sub_Sub_Category = request.form.get('Sub_Sub_Category', '')
        additional_input = request.form.get('additional_input', '')
        itemname = request.form['itemname']
        invoice_number = request.form.get('invoice_number', '')
        Currency = request.form['Currency']
        Rate = request.form['Rate']
        amount = float(request.form['amount']) if 'amount' in request.form else 0.0
        gst_percent = request.form['gst_percent'] if 'gst_percent' in request.form else ''
        gst_value = request.form['gst_value'] if 'gst_value' in request.form else ''
        Remarks = request.form.get('Remarks', '')
        total = float(request.form['total']) if 'total' in request.form else 0.0
        # Check if gst_percent is a valid numeric value
        if 'gst_percent' in request.form and request.form['gst_percent'].strip():
            try:
                gst_percent = float(request.form['gst_percent'])
            except ValueError:
                gst_percent = 0.0
        else:
            gst_percent = 0.0
        # Check if gst_value is a valid numeric value
        if 'gst_value' in request.form and request.form['gst_value'].strip():
            try:
                gst_value = float(request.form['gst_value'])
            except ValueError:
                gst_value = 0.0
        else:
            gst_value = 0.0

        if gst_percent != 0.0:
            gst = round(amount * (gst_percent / 100.0), 2)
        elif gst_value != 0.0:
            gst = round(gst_value, 2)
        else:
            gst = 0.0
        calculated_total = amount + gst
        existed_claim = request.form.get('existed_claim', '')

        category_mapping = {'2000': 'Material', '3000': 'Sub-Con', '4000': 'Category 400', '500': 'Others', '501': 'Admin',
            '502': 'Salary',
            '503': 'Levy',
            '504': 'CPF',
            '505': 'Asset',
            '506': 'Vehicle',
            '507': 'Training',
            '508': 'Insurance',
            '509': 'Renewal',
            '510': 'Utilities',
            '511': 'Medical',
            '512': 'Travel',
            '513': 'Rental',
            '514': 'Safety',
            '515': 'Food',
            '516': 'Entertainment',
            '517': 'Others'}

        sub_category_mapping = {
            '2001': 'Mechanical',
            '2002': 'Electrical',
            '2003': 'Instruments',
            '2004': 'PLC, Software, Hardware',
            '2005': 'Consumable',
            '2006': 'Panel Hardware',
            '2007': 'Tools',
            '2008': 'Civil',
            '3001': 'Scaffolding',
            '3002': 'Programming',
            '3003': 'E&I Fabrication',
            '3004': 'Mechanical Fabrication',
            '3005': 'Manpower Supply',
            '3006': 'LEW',
            '3007': 'Calibration',
            '3008': 'Equipment Rent',
            '3009': 'Servicing',
            '3010': 'Others',
            '4001': 'Category 401',
            '4002': 'Category 402',
            '4003': 'Category 403',
            '4004': 'Category 404',
            '501': 'Admin',
            '502': 'Salary',
            '503': 'Levy',
            '504': 'CPF',
            '505': 'Asset',
            '506': 'Vehicle',
            '507': 'Training',
            '508': 'Insurance',
            '509': 'Renewal',
            '510': 'Utilities',
            '511': 'Medical',
            '512': 'Travel',
            '513': 'Rental',
            '514': 'Safety',
            '515': 'Food',
            '516': 'Entertainment',
            '517': 'Others'
        }

        sub_sub_category_mapping = {

                '11': 'Office Consumables',
                '12': 'Pantry',
                '13': 'Repair Works',
                '14': 'Furniture',
                '15': 'Others',

                '21': 'Basic',
                '22': 'Allowance',
                '23': 'Overtime',
                '24': 'Deduction',
                '25': 'Bonus',
                '26': 'Others',

                '41': 'CPF',
                '42': 'Employee',

                '51': 'Property',
                '52': 'Computers, Printer, Phone',
                '53': 'Vehicle',
                '54': 'Machines',
                '55': 'Tools',
                '56': 'Instruments',
                '57': 'Fan, Air-Con',
                '58': 'Others',

                '61': 'Loan / Rental',
                '62': 'Fuel',
                '63': 'Parking',
                '64': 'Toll',
                '65': 'Maintenance',

                '91': 'Permit Application',
                '92': 'Permit Issuance',
                '93': 'Medical Check Up',
                '94': 'Others',

                '101': 'Telephone, Internet',
                '102': 'Water, Gas, Electricity',

                '111': 'General',
                '112': 'Special',
                '113': 'Surgery',
                '114': 'Others',

                '121': 'Flight',
                '122': 'T',

                '131': 'Office',
                '132': 'Dormitory',
                '133': 'Staff Accommodation',

                '141': 'PPE',
                '142': 'Meeting',
                '143': 'Awards',
        }

        # Map category to code
        Category_name = category_mapping.get(Category, '')

        # Map sub-category to code
        Sub_Category_name = sub_category_mapping.get(Sub_Category, '')
        sub_Sub_Category_name = sub_sub_category_mapping.get(Sub_Sub_Category, '')

        try:
            sql = '''INSERT INTO temp_expences (claim_by, date, projectid, project_name, Category, Category_code, Sub_Category, Sub_Category_code, Sub_Sub_Category, Sub_Sub_Category_code, vendor, itemname,
                                                Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input)
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

            params = (username, date, projectid, project_name, Category_name, Category, Sub_Category_name, Sub_Category, sub_Sub_Category_name, Sub_Sub_Category, vendor, itemname,
                     Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input)

            cursor.execute(sql, params)
            db.commit()
            # print("data inserted,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,")
            cursor.execute('SELECT * FROM temp_expences WHERE claim_by = ?', (username,))
            claims_data = cursor.fetchall()
            cursor.execute('SELECT SUM(total) FROM temp_expences WHERE claim_by = ?', (username,))
            total_sum = cursor.fetchone()[0]  # Fetch the total sum value

            if total_sum  is not None:
                rounded_total_sum = round(total_sum, 2)
                # print(f'Total sum of amount for user: {rounded_total_sum}')
            else:
                rounded_total_sum = 0


            if existed_claim.strip():  # Check if existed_claim has some values

                return render_template('admin_templates/accounts/Expenses.html', is_pm=is_pm, department_code=department_code, itemname_suggestions=itemname_suggestions, user=user, claims_data=claims_data,
                           rounded_total_sum=rounded_total_sum, existed_claim=existed_claim,vendor_suggestions=vendor_suggestions, project_ids=project_ids)
            else:

                return redirect(url_for('Expenses'))
        except sqlite3.Error as e:
            print("SQLite error:", e)
            db.rollback()
            return render_template('admin_templates/accounts/Expenses.html', is_pm=is_pm, department_code=department_code, user=user, enq_ids=enq_ids, claims_data=claims_data, project_ids=project_ids, error_message="An error occurred.")
    # print("..............enq_ids..............",enq_ids)
    return render_template('admin_templates/accounts/Expenses.html', is_pm=is_pm, department_code=department_code, itemname_suggestions=itemname_suggestions, user=user, claims_data=claims_data,
                          rounded_total_sum=rounded_total_sum,enq_ids=enq_ids, vendor_suggestions=vendor_suggestions, project_ids=project_ids)

@app.route('/generate_expense', methods=['GET', 'POST'])
@login_required
def generate_expense():
    if request.method == 'POST':
        db = get_database()
        cursor = db.cursor()
        data_list = []

        if 'Claim' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            overall_amount = 0.0
            overall_gst = 0.0
            overall_total = 0.0

            cursor.execute('SELECT id FROM Expenses ORDER BY id DESC LIMIT 1')
            result = cursor.fetchone()
            current_year = datetime.now().year

            existed_claim = request.form.get('Claim')

            if existed_claim and existed_claim.strip():
                parts = existed_claim.split('-')
                if len(parts) == 3:
                    prefix, year_part, claim_no_part = parts
                    latest_claim_no = f"{existed_claim}-01"
                elif len(parts) == 4:
                    prefix, year_part, claim_no_part, revision = parts
                    new_revision = int(revision) + 1
                    formatted_revision = f"{new_revision:02}"
                    latest_claim_no = f"{prefix}-{year_part}-{claim_no_part}-{formatted_revision}"

                cursor.execute('DELETE FROM Expenses WHERE claim_id = ?', (existed_claim,))
                cursor.execute('DELETE FROM expences_items WHERE claim_no = ?', (existed_claim,))

            else:
                if result:
                    lat_claim_no = result[0]
                else:
                    lat_claim_no = 0
                temp_claim_no = lat_claim_no + 1
                latest_claim_no = f"E-{str(current_year)[-2:]}-{temp_claim_no}"
                print(".............latest_claim_no.....................",latest_claim_no)

            try:

                for claim_id in claimdata:
                    print("..claim_id..............",claim_id)
                    cursor.execute('SELECT * FROM temp_expences WHERE id = ?', (claim_id,))
                    existing_data = cursor.fetchone()
                    if existing_data:
                        columns = [col[0] for col in cursor.description]
                        claim_data = dict(zip(columns, existing_data))

                        overall_amount += float(claim_data['amount'])
                        overall_gst += float(claim_data['gst'])
                        overall_total += float(claim_data['total'])

                        cursor.execute('''
                            INSERT INTO expences_items (claim_by, date, projectid, project_name, Category, Category_code,Sub_Category, Sub_Category_code, Sub_Sub_Category, Sub_Sub_Category_code,
                                                    vendor, itemname, Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input, claim_no)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (claim_data['claim_by'], claim_data['date'], claim_data['projectid'], claim_data['project_name'],claim_data['Category'], claim_data['Category_code'], claim_data['Sub_Category'],
                            claim_data['Sub_Category_code'], claim_data['Sub_Sub_Category'], claim_data['Sub_Sub_Category_code'],claim_data['vendor'], claim_data['itemname'], claim_data['Currency'],
                            claim_data['Rate'], claim_data['invoice_number'], claim_data['amount'], claim_data['gst_percent'], claim_data['gst_value'], claim_data['Remarks'], claim_data['gst'],
                            claim_data['total'], claim_data['additional_input'], latest_claim_no))

                        cursor.execute('DELETE FROM temp_expences WHERE id = ?', (claim_id,))

                        db.commit()

                user = get_current_user()['name']
                current_date = datetime.now().date()
                overall_total = round(overall_total, 2)
                overall_amount = round(overall_amount, 2)
                overall_gst = round(overall_gst, 2)

                cursor.execute(''' INSERT INTO Expenses (claim_by, claim_id, claim_date, status, claim_Total) VALUES (?, ?, ?, ?, ?)''', (user, latest_claim_no, current_date, 'Open', overall_total))
                db.commit()
                return redirect(url_for('Expenses'))

            except Exception as e:
                db.rollback()
                flash(f'Error generating claims: {str(e)}', 'error')
                return redirect(url_for('Expenses'))

        if 'Delete' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            try:
                for claim_id in claimdata:
                    print("yes")
                    cursor.execute('DELETE FROM temp_expences WHERE id = ?', (claim_id,))

                db.commit()
                flash('Selected claims deleted successfully.', 'success')
            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')

    return redirect(url_for('Expenses'))

@app.route('/client_details', methods=["POST", "GET"])
@login_required
def client_details():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM client_details')
    client_details = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT Client_code FROM client_details ORDER BY id DESC LIMIT 1')
    max_client_code_row = cursor.fetchone()

    if max_client_code_row:
        max_client_code = max_client_code_row[0]
        # Extract the numeric part and increment
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1
    else:
        # Handle the case when no client codes are found
        new_numeric_part = 1  # or any default value you want to assign
        # export_client_details()

    new_client_code = f'C - {new_numeric_part:04d}'

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
        try:
            db.execute(
                'INSERT INTO client_details (Client_code,display_name, reg_no, company_name, fax, office_no, website, billing_address1, billing_address2, billing_city, billing_postcode, billing_country, billing_state,delivery_address1,delivery_address2,delivery_city, delivery_postcode,delivery_country, delivery_state,contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [Client_code, display_name,reg_no, company_name, fax, office_no, website, billing_address1, billing_address2, billing_city, billing_postcode, billing_country, billing_state,delivery_address1,delivery_address2, delivery_city,delivery_postcode,delivery_country,delivery_state,contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3])
            db.commit()
            flash(f"Client details for '{company_name}' are successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add client details. Please try again.", 'error')

        cursor = db.execute('SELECT * FROM client_details')
        client_details = cursor.fetchall()
        cursor = db.execute('SELECT Client_code FROM client_details ORDER BY id DESC LIMIT 1')
        max_client_code = cursor.fetchone()[0]

        # Extract the numeric part and increment
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1

        # Format the new Client_code with leading zeros
        new_client_code = f'C - {new_numeric_part:04d}'
        return render_template('admin_templates/accounts/client_details.html', user=user,client_details=client_details,department_code=department_code,new_client_code=new_client_code)

    return render_template('admin_templates/accounts/client_details.html', user=user,client_details=client_details,department_code=department_code,new_client_code=new_client_code)

@app.route('/client_details_edit', methods=["POST", "GET"])
@login_required
def client_details_edit():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.execute('SELECT * FROM client_details')
    client_details = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])

    if request.method == 'GET':
        id = request.args.get('id')
        cursor = db.execute("SELECT * FROM client_details WHERE id = ?", (id,))
        client_values = dict(cursor.fetchone())  # Convert to dictionary
        if client_values is None:
            flash('Enquiry not found', 'error')
            return redirect(url_for('client_details'))
        cursor = db.execute('SELECT * FROM client_details')
        client_details = cursor.fetchall()
        return render_template("admin_templates/accounts/client_details_edit.html", client_values=client_values, user=user, client_details=client_details, department_code=department_code)

    if request.method == "POST":
        id = request.form['id']
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

        try:
            db.execute(''' UPDATE client_details SET Client_code= ?,reg_no= ?,company_name= ?,display_name=?,fax= ?,office_no= ?,website= ?,billing_address1= ?,billing_address2= ?,billing_city= ?,billing_postcode= ?,
                billing_country= ?,billing_state= ?,delivery_address1= ?,delivery_address2= ?,delivery_city= ?,delivery_postcode= ?,delivery_country= ?,delivery_state= ?,contact1= ?,
                email1= ?,mobile1= ?,contact2= ?,email2= ?,mobile2= ?,contact3= ?,email3= ?,mobile3= ? WHERE id = ? ''',
                [Client_code, reg_no, company_name,display_name, fax, office_no, website, billing_address1, billing_address2, billing_city, billing_postcode, billing_country, billing_state,delivery_address1,delivery_address2,
                delivery_city,delivery_postcode,delivery_country,delivery_state,contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3,id])
            db.commit()
            flash(f"Client details for '{company_name}' are successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add client details. Please try again.", 'error')

        cursor = db.execute('SELECT * FROM client_details')
        client_details = cursor.fetchall()
        cursor = db.execute('SELECT Client_code FROM client_details ORDER BY id DESC LIMIT 1')
        max_client_code = cursor.fetchone()[0]

        # Extract the numeric part and increment
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1

        # Format the new Client_code with leading zeros
        new_client_code = f'C - {new_numeric_part:04d}'
        return render_template('admin_templates/accounts/client_details.html', user=user,client_details=client_details,department_code=department_code,new_client_code=new_client_code)

    return render_template('admin_templates/accounts/client_details.html', user=user,client_details=client_details,department_code=department_code)

@app.route('/vendor', methods=["POST", "GET"])
@login_required
def vendor():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM vendors_details')
    vendors = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
    max_client_code_row = cursor.fetchone()

    if max_client_code_row:
        max_client_code = max_client_code_row[0]
        # Extract the numeric part and increment
        numeric_part = int(max_client_code.split('-')[-1])
        new_numeric_part = numeric_part + 1
    else:
        # Handle the case when no client codes are found
        new_numeric_part = 1  # or any default value you want to assign
        # export_client_details()

    new_vendor_code = f'V - {new_numeric_part:04d}'

    if request.method == "POST":

        if 'Delete' in request.form:
            # print("...................in the delete form")
            vendordata = request.form.getlist('vendordata[]')
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in vendordata:
                    claim_id = claim_str.split('|')[0]
                    # print("...............id............", claim_id)
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
        try:
            db.execute(
                'INSERT INTO vendors_details (vendor_code, reg_no, company_name,display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, swift, ifsc) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [vendor_code, reg_no, company_name,display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3, mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, swift, ifsc])
            db.commit()
            flash(f"Client details for '{company_name}' are successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add client details. Please try again.", 'error')

        cursor = db.execute('SELECT * FROM vendors_details')
        vendors = cursor.fetchall()
        cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
        max_vendor_code = cursor.fetchone()[0]

        # Extract the numeric part and increment
        numeric_part = int(max_vendor_code.split('-')[-1])
        new_numeric_part = numeric_part + 1

        # Format the new Client_code with leading zeros
        new_vendor_code = f'V - {new_numeric_part:04d}'
        return render_template('admin_templates/accounts/vendor.html', user=user,vendors=vendors,department_code=department_code,new_vendor_code=new_vendor_code)

    return render_template('admin_templates/accounts/vendor.html', user=user,vendors=vendors,department_code=department_code,new_vendor_code=new_vendor_code)

@app.route('/vendor_edit', methods=["POST", "GET"])
@login_required
def vendor_edit():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.execute('SELECT * FROM vendors_details')
    vendors = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
    max_vendor_code = cursor.fetchone()[0]

    # Extract the numeric part and increment
    numeric_part = int(max_vendor_code.split('-')[-1])
    new_numeric_part = numeric_part + 1

    # Format the new Client_code with leading zeros
    new_vendor_code = f'V - {new_numeric_part:04d}'

    if request.method == 'GET':
        id = request.args.get('id')
        cursor = db.execute("SELECT * FROM vendors_details WHERE id = ?", (id,))
        vendors_details = dict(cursor.fetchone())  # Convert to dictionary
        if vendors_details is None:
            flash('Enquiry not found', 'error')
            return redirect(url_for('vendor'))
        cursor = db.execute('SELECT * FROM vendors_details')
        vendors = cursor.fetchall()
        return render_template("admin_templates/accounts/vendor_edit.html", vendors_details=vendors_details, user=user, vendors=vendors, department_code=department_code)


    if request.method == "POST":
        id = request.form['id']
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
        try:
            db.execute('''UPDATE vendors_details SET vendor_code = ?, reg_no = ?, company_name = ?,display_name=?, office_no = ?, website = ?, billing_address1 = ?, billing_address2 = ?, city = ?, postcode = ?, country = ?,
                state = ?,contact1 = ?, email1 = ?, mobile1 = ?, contact2 = ?, email2 = ?, mobile2 = ?, contact3 = ?, email3 = ?, mobile3 = ?, bank_name = ?, tax_id = ?,
                branch_details = ?, currency = ?, pay_terms = ?, account_no = ?, swift = ?, ifsc = ? WHERE id = ? ''',
                [vendor_code, reg_no, company_name,display_name, office_no, website, billing_address1, billing_address2, city, postcode, country, state, contact1, email1, mobile1, contact2, email2, mobile2, contact3, email3,
                 mobile3, bank_name, tax_id, branch_details, currency, pay_terms, account_no, swift, ifsc, id])
            db.commit()
            flash(f"Client details for '{company_name}' are successfully added.", 'success')

        except sqlite3.IntegrityError:
            flash("Failed to add client details. Please try again.", 'error')

        cursor = db.execute('SELECT * FROM vendors_details')
        vendors = cursor.fetchall()
        cursor = db.execute('SELECT vendor_code FROM vendors_details ORDER BY id DESC LIMIT 1')
        max_vendor_code = cursor.fetchone()[0]

        # Extract the numeric part and increment
        numeric_part = int(max_vendor_code.split('-')[-1])
        new_numeric_part = numeric_part + 1

        # Format the new Client_code with leading zeros
        new_vendor_code = f'V - {new_numeric_part:04d}'
        return render_template('admin_templates/accounts/vendor.html', user=user,vendors=vendors,department_code=department_code,new_vendor_code=new_vendor_code)

    return render_template('admin_templates/accounts/vendor.html', user=user,vendors=vendors,department_code=department_code,new_vendor_code=new_vendor_code)

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






##--------------------------------------------------------PURCHASE------------------------------------------------------------------------------------------------------------------

@app.route('/purchase',methods=['GET', 'POST'])
@login_required
def purchase():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    user_name = user['name']
    db = get_database()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM created_po WHERE stat = 'pending' AND created_by = ?", (user_name,))
    PR_pending_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_po WHERE created_by = ?", (user_name,))
    PR_count = cursor.fetchone()[0]


    cursor.execute("SELECT COUNT(*) FROM claims WHERE claim_by = ?", (user_name,))
    user_total_claims = cursor.fetchone()[0]

    # Query to get the number of claims where the status is not approved
    cursor.execute("SELECT COUNT(*) FROM claims  WHERE status != 'Approved' AND  claim_by = ?", (user_name,))
    user_unapproved_claims = cursor.fetchone()[0]

    return render_template('admin_templates/purchase/purchase_main_page.html',user=user,department_code=department_code,PR_pending_count=PR_pending_count,PR_count=PR_count,
                           user_total_claims=user_total_claims,user_unapproved_claims=user_unapproved_claims)

@app.route('/Material_Receipt',methods=['GET', 'POST'])
@login_required
def Material_Receipt():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM projects')
    return render_template('admin_templates/purchase/Material_Receipt.html',is_pm=is_pm,department_code=department_code,user=user)

@app.route('/project_name')
def project_name():
    db = get_database()
    project_id = request.args.get('project_id')
    cursor = db.execute('SELECT project_name FROM projects WHERE id = ?', (project_id,))
    project_name = cursor.fetchone()[0]
    db.commit()
    return jsonify(project_name) if project_name else jsonify({"none"})

@app.route('/pdashboard', methods=['GET', 'POST'])
@login_required
def pdashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    username = user['name']
    stat = 'pending'
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor = cursor.execute('SELECT * FROM created_po WHERE stat = ? ORDER BY id DESC', (stat,))
    created_po = cursor.fetchall()
    cursor.execute("SELECT * FROM po_items where  po_number = ? ",('123-1000-1061',))
    items = cursor.fetchall()

    return render_template('admin_templates/purchase/purchase_dashboard.html', is_pm=is_pm, department_code=department_code, user=user,created_po=created_po,items=items)

import requests
from shareplum import Office365
# from config_template import config
import logging

def to_sharepoint(pdf_content, latest_claim_no):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # get data from configuration
    username = config['sp_user']
    password = config['sp_password']
    site_name = config['sp_site_name']
    base_path = config['sp_base_path']
    doc_library = config['sp_doc_library']

    # Obtain auth cookie
    authcookie = Office365(base_path, username=username, password=password).GetCookies()
    print("...........url......",base_path)
    session = requests.Session()
    session.cookies = authcookie
    session.headers.update({'user-agent': 'python_bite/v1'})
    session.headers.update({'accept': 'application/json;odata=verbose'})

    response = session.get(base_path + "/_api/web/currentuser")
    response.raise_for_status()  # This line will raise an exception if the status code is not 2xx

    print("Successfully logged in to SharePoint.")



    session.headers.update({'X-RequestDigest': 'FormDigestValue'})
    response = session.post(
        url=base_path + "/_api/web/GetFolderByServerRelativeUrl('" + doc_library + "')/Files/add(url='" + latest_claim_no + ".pdf',overwrite=true)",
        data=""
    )
    print("............response.....",response)
    session.headers.update({'X-RequestDigest': response.headers['X-RequestDigest']})

    # Update the upload URL
    upload_url = (
        f"{base_path}/_api/web/GetFolderByServerRelativeUrl('"
        f"{doc_library}')/Files/add(url='{latest_claim_no}.pdf',overwrite=true)"
    )
    print("...................upload url .................", upload_url )


    # Perform the actual upload with PDF content
    try:
        # print(f"................upload url............{base_path}/{doc_library}")
        response = session.post(url=upload_url, data=pdf_content)
        # print(f"................upload url............{base_path}/{doc_library}")
        response.raise_for_status()
        print("File uploaded successfully.")
        print(f"File uploaded successfully to: {base_path}/{doc_library}/{latest_claim_no}.pdf")
        # print(f"................upload url............{base_path}/{doc_library}")

    except Exception as err:
        print(f"................upload url............{base_path}/{doc_library}")
        print("Error occurred during upload:", str(err))
        print("Response content:", response.content)

    return()


@app.route('/pedashboard', methods=['GET', 'POST'])
@login_required
def pedashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    po_number = request.args.get('id')
    cursor.execute("SELECT * FROM po_items where  po_number = ? ",(po_number,))
    items = cursor.fetchall()
    cursor.execute("SELECT * FROM created_po where  po_number = ? ",(po_number,))
    po_data = cursor.fetchone()
    stat = 'pending'
    cursor = cursor.execute('SELECT * FROM created_po WHERE stat = ? ORDER BY id DESC', (stat,))
    created_po = cursor.fetchall()

    if request.method == 'POST':
        action_value = request.form.get('action')
        print("..............action_value",action_value)
        if action_value == 'pedashboard':
            print("sairammmmmmmmmmmmmmmmmmmmmmmmmmmm")
            po_number = request.form.get('po_number')
            po_date = request.form.get('po_date')
            proj_no = request.form.get('projectid',type=int)
            client = request.form.get('client')
            delivery_address = request.form.get('delivery_address')
            created_by = user['name']
            terms = request.form.get('terms')
            currency = request.form.get('currency')
            delivery = request.form.get('delivery')
            Contact = request.form.get('Contact')
            status = request.form.get('status')
            Approvedby = request.form.get('Approvedby')
            phone_number = request.form.get('phone_number')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            cursor = db.cursor()
            user = user['name']
            db.execute(''' UPDATE created_po SET Comments= ?,Approved_date= ?,Approvedby= ? WHERE po_number = ? ''',[Comments,Approved_date,Approvedby,po_number])
            cursor.execute("SELECT id,item, username, unit_price, quantity, total FROM po_items WHERE po_number = ?", (po_number,))
            items = cursor.fetchall()
            total_sum = 0
            db.commit()

            # Construct the PDF filename
            pdf_filename = f'C:/Users/Hewlett Packard/Desktop/do/{po_number}.pdf'
            print(pdf_filename)
            c = canvas.Canvas(pdf_filename, pagesize=letter)
            c = po_pdf(c, po_number, po_date, proj_no, client,created_by,terms,currency,delivery,Contact,phone_number,delivery_address, items,total_sum)
            c.setFillColorRGB(0, 0, 1)
            c.setFont("Helvetica", 16)
            # c.drawString(2 * inch, 4 * inch, 'List of items')
            c.showPage()
            c.save()




    return render_template('admin_templates/purchase/pedashboard.html',department_code=department_code,user=user,po_data=po_data,items=items,created_po=created_po)

@app.route('/delete_pur_pe/<int:poid>', methods=["GET", "POST"])
@login_required
def delete_pur_pe(poid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM created_po WHERE id = ?', [poid])
        db.commit()
        return redirect(url_for('pedashboard'))
    return render_template('pedashboard.html', user=user)

@app.route('/delete_pur_item/<int:id>', methods=["GET", "POST"])
@login_required
def delete_pur_item(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute("DELETE FROM po_items WHERE id = ?", (id,))
        db.commit()
        return redirect(url_for('pedashboard'))
    return render_template('pedashboard.html', user=user)

@app.route('/purchase_po',methods=['GET', 'POST'])
@login_required
def purchase_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.args.get('project_id', type=int)
    cursor = db.cursor()
    cursor.execute("SELECT * FROM temp_po_items where  username = ? ",(user['name'],))
    items = cursor.fetchall()
    po_total = sum(row['total'] for row in items)
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = cursor.execute('SELECT * FROM created_po WHERE user = ? ORDER BY id DESC', (user['name'],))
    created_po = cursor.fetchall()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    cursor = db.execute("SELECT MAX(id) FROM created_po")
    result = cursor.fetchone()
    serial_number = result[0]
    expences_code = 1000
    new_po_number = f"{project_id}-{expences_code:04d}-{serial_number:04d}"
    # print(".............new_po_number..............",new_po_number)
    cursor.execute('SELECT company_name FROM vendors_details')
    company_names = [row[0] for row in cursor.fetchall()]

    if request.method == 'POST':
        action_value = request.form.get('action')
        if action_value == 'purchase_po':
            po_number = request.form.get('po_number')
            po_date = request.form.get('po_date')
            proj_no = request.form.get('projectid',type=int)
            client = request.form.get('client')
            delivery_address = request.form.get('delivery_address')
            created_by = user['name']
            terms = request.form.get('terms')
            currency = request.form.get('currency')
            delivery = request.form.get('delivery')
            Contact = request.form.get('Contact')
            status = request.form.get('status')
            phone_number = request.form.get('phone_number')
            cursor = db.cursor()
            user = user['name']
            npo_number = f"{proj_no}-{expences_code:04d}-{serial_number:04d}"
            # print("//////////////status............",status)
            stat = 'pending'
            cursor.execute('''INSERT INTO created_po (user,po_number, po_date, proj_no, client, status,created_by,terms,currency,delivery,Contact,phone_number,delivery_address,stat) VALUES (?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?,?, ?)''',
                        (user,npo_number, po_date, proj_no, client, status,created_by,terms,currency,delivery,Contact,phone_number,delivery_address,stat))

            cursor.execute("SELECT id,item, username, unit_price, quantity, total FROM temp_po_items WHERE username = ?", (user,))
            items = cursor.fetchall()
            total_sum = 0
            for row in items:
                id, item, username, unit_price, quantity, total = row[0],row[1], row[2], row[3], row[4], row[5]
                cursor.execute("INSERT INTO po_items (project_id, po_number, item, username, unit_price, quantity, total) VALUES (?, ?, ?, ?, ?, ?, ?)",(proj_no, npo_number, item, username, unit_price, quantity, total))
                # Calculate the sum of the 'total' column
                total_sum = sum(row['total'] for row in items)
                db.execute("DELETE FROM temp_po_items WHERE id = ?", (id,))

            cursor.execute("SELECT * FROM temp_po_items where  username = ? ",(user,))
            items = cursor.fetchall()
            cursor = cursor.execute('SELECT * FROM created_po WHERE user = ? ORDER BY id DESC', (user,))
            created_po = cursor.fetchall()
            db.commit()

            return render_template('admin_templates/purchase/purchase_po.html', current_date=formatted_date, is_pm=is_pm, department_code=department_code, items=items,
                              company_names=company_names,new_po_number=new_po_number, usernames=usernames, project_ids=project_ids,user=user,created_po=created_po)

        elif 'action' in request.form and request.form['action'] == 'add_po_item':
            item = request.form.get('Description')
            quantity = request.form.get('quantity',type=int)
            unit_price = request.form.get('unit_price',type=int)
            username = user['name']
            total = quantity * unit_price
            cursor.execute('''INSERT INTO temp_po_items (item, username, unit_price, quantity, total) VALUES (?, ?, ?, ?, ?)''', (item, username, unit_price, quantity, total))
            cursor.execute("SELECT * FROM temp_po_items where  username = ? ",(user['name'],))
            items = cursor.fetchall()
            po_total = sum(row['total'] for row in items)

            db.commit()

            return render_template('admin_templates/purchase/purchase_po.html', current_date=formatted_date, is_pm=is_pm, department_code=department_code, items=items,po_total=po_total,
                              company_names=company_names,total=total,new_po_number=new_po_number, usernames=usernames, project_ids=project_ids,user=user,created_po=created_po)


    return render_template('admin_templates/purchase/purchase_po.html',current_date=formatted_date,is_pm=is_pm, department_code=department_code,items=items,po_total=po_total,
                              company_names=company_names,new_po_number=new_po_number,usernames=usernames, project_ids=project_ids, created_po=created_po,user=user)

def po_pdf(c, npo_number, po_date, proj_no, client,created_by,terms,currency,delivery,Contact,phone_number,delivery_address, items,total_sum):
    c.translate(inch, inch)

    # Define a large font
    c.setFont("Helvetica", 10)

    # Centroid logo resized image
    image_path = 'templates/admin_templates/projects/ces.jpeg'
    image_width = 2  # Set the desired width in inches
    image_height = 0.3  # Set the desired height in inches
    c.drawImage(image_path, 4.7 * inch, 9.3 * inch, width=image_width * inch, height=image_height * inch)

    # Centroid Address
    c.drawString(0.02 * inch, 9.5 * inch, "Centroid Engineering Solutions Pte Ltd")
    c.drawString(0.02 * inch, 9.3 * inch, "Co  Regn No: 201308058R")
    c.drawString(0.02 * inch, 9.1 * inch, "GST Regn No: 201308058R")
    c.drawString(0.02 * inch, 8.9 * inch, "11, Woodlands Close, #07-10")
    c.drawString(0.02 * inch, 8.7 * inch, "Singapore - 737853")

    # Delivery order
    c.setFont("Helvetica-Bold", 15)
    c.drawString(2.7 * inch, 8.7 * inch, 'PURCHASE ORDER')

    #First line from top
    c.setFillColorRGB(0, 0, 0)  # Font colour
    c.line(0, 8.6 * inch, 6.8 * inch, 8.6 * inch)
    #Second line
    c.line(0, 7.5 * inch, 6.8 * inch, 7.5 * inch)
    #Third line
    c.line(0, 6.6 * inch, 6.8 * inch, 6.6 * inch)
    #Fourth line
    c.line(0, 6.3 * inch, 6.8 * inch, 6.3 * inch)
    #top line
    c.line(0, 9.7 * inch, 6.8 * inch, 9.7 * inch)
    #half line
    c.line(4.6 * inch, 1.2 * inch, 6.8 * inch, 1.2 * inch)
    c.line(4.6 * inch, 0.9 * inch, 6.8 * inch, 0.9 * inch)
    c.line(4.6 * inch, 0.6 * inch, 6.8 * inch, 0.6 * inch)

    #Vertical Lines
    c.line(0.0 * inch, 9.7 * inch, 0.0 * inch, -0.7 * inch)
    c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, 1.5 * inch)
    c.line(4.6 * inch, 6.6 * inch, 4.6 * inch, 0.6 * inch)
    c.line(5.1 * inch, 6.6 * inch, 5.1 * inch, 1.5 * inch)
    c.line(5.9 * inch, 6.6 * inch, 5.9 * inch, 0.6 * inch)
    c.line(6.8 * inch, 9.7 * inch, 6.8 * inch, -0.7 * inch)

    # Client
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 8.4 * inch, 'Client')
    c.drawString(0.7 * inch, 8.4 * inch, 'Centroid Engineering Solutions')

    # Client Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 8.2 * inch, 'No.2 Venture Drive, #22-28')
    c.drawString(0.7 * inch, 8.0 * inch, 'Vision Exchange')
    c.drawString(0.7 * inch, 7.8 * inch, 'Singapore')

    # Attn
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 7.6 * inch, 'Attn')
    c.drawString(0.7 * inch, 7.6 * inch, 'Mr. George Kyaw')

    # DO NO, Date, Po, Qoute Ref, Page
    c.setFont("Helvetica-Bold", 10)
    c.drawString(4.8 * inch, 8.4 * inch, 'PO No')
    c.drawString(4.8 * inch, 8.2 * inch, 'PO Date')
    c.drawString(4.8 * inch, 8.0 * inch, 'Terms')
    c.drawString(4.8 * inch, 7.8 * inch, 'Currency')
    # c.drawString(4.8 * inch, 7.6 * inch, 'Quote Ref')
    # Values
    c.setFont("Helvetica", 10)
    c.drawString(5.6 * inch, 8.4 * inch, npo_number)
    c.drawString(5.6 * inch, 8.2 * inch, po_date)
    c.drawString(5.6 * inch, 8.0 * inch, terms)
    c.drawString(5.6 * inch, 7.8 * inch, currency)
    # c.drawString(5.6 * inch, 7.6 * inch, '3775')

    # Delivery
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 7.3 * inch, 'Delivery')
    c.drawString(0.7  * inch, 7.3 * inch, 'Centroid Engineering Solutions Pte Ltd')

    # Delivery Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 7.1 * inch, '11, Woodlands close')
    c.drawString(0.7 * inch, 6.9 * inch, '#07-10')
    c.drawString(0.7 * inch, 6.7 * inch, 'Singapore - 737853')

    # DO NO, Date, Po, Qoute Ref, Page
    c.setFont("Helvetica-Bold", 10)
    c.drawString(4.8 * inch, 7.3 * inch, 'Delivery')
    c.drawString(4.8 * inch, 7.1 * inch, 'Contact')
    # c.drawString(4.8 * inch, 6.9* inch, 'Terms')
    c.drawString(4.8 * inch, 6.7 * inch, 'Page')

    # Values
    c.setFont("Helvetica", 10)
    c.drawString(5.6 * inch, 7.3 * inch, delivery)
    c.drawString(5.6 * inch, 7.1 * inch, Contact)
    c.drawString(5.6 * inch, 6.9 * inch, phone_number)
    c.drawString(5.6 * inch, 6.7 * inch, '1 of 1')

    #Item table heading
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 6.4 * inch, 'S.No')
    c.drawString(2.3 * inch, 6.4 * inch, 'Item Description')
    c.drawString(4.7 * inch, 6.4 * inch, 'Qty')
    c.drawString(5.2 * inch, 6.4 * inch, 'Unit Price')
    c.drawString(6.0 * inch, 6.4 * inch, 'Total Price')

    # Draw items in a table
    row_height = 0.3 * inch  # Adjust as needed
    start_y = 6.0 * inch  # Adjust as needed
    for index, item_row in enumerate(items):
        _, item, _, quantity, unit_price, total_price = item_row
        current_y = start_y - index * row_height
        c.setFont("Helvetica", 10)
        c.drawString(0.2 * inch, current_y, str(index + 1))
        c.drawString(0.7 * inch, current_y, item)
        c.drawString(4.78 * inch, current_y, str(unit_price) )
        c.drawString(5.2 * inch, current_y, f"{quantity:.2f}")
        c.drawString(6.0 * inch, current_y, f"{total_price:.2f}")

    #ref
    c.drawString(0.1 * inch, 1.3 * inch, 'Ref')
    # c.setFont("Helvetica", 10)
    c.drawString(0.8 * inch, 1.0 * inch, '2016019729')

    c.setFont("Helvetica-Bold", 10)
    c.drawString(5.15 * inch, 1.3 * inch, 'Total')
    c.drawString(5.05 * inch, 1.0 * inch, 'GST (8%)')
    c.drawString(5.15* inch, 0.7 * inch, 'Total')

    c.setFont("Helvetica", 10)


    gst_percentage = 8
    gst = (gst_percentage / 100) * total_sum  # Calculate gst before using it
    final_total = total_sum + gst

    c.drawString(5.95 * inch, 1.3 * inch, f"$  {total_sum:.2f}")  # Use total_sum here
    c.drawString(5.95 * inch, 1.0 * inch, f"$  {gst:.2f}")
    c.drawString(5.95 * inch, 0.7 * inch, f"$  {final_total:.2f}")



    #Signature
    c.drawString(0.8 * inch, -0.4 * inch, 'Acknowledged & Accepted By')
    c.drawString(4.5 * inch, -0.4 * inch, 'for Centroid Engineering Solutions')
    c.drawString(2.0 * inch, -0.65 * inch, 'This is a system generated PO signature not required.')


    c.line(0, 1.5 * inch, 6.8 * inch, 1.5 * inch)
    # c.line(0, -0.5 * inch, 6.8 * inch, -0.5 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)
    c.line(0, -0.2 * inch, 6.8 * inch, -0.2 * inch)


    return c

@app.route('/purchase_po_edit', methods=['GET', 'POST'])
@login_required
def purchase_po_edit():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    do_number_variable = request.args.get('po_id')
    project_id = request.args.get('proj_no', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM po_items")
    items = cursor.fetchall()

    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
    created_po = cursor.fetchall()

    if request.method == 'POST':
        item = request.form.get('item')
        uom = request.form.get('uom')
        quantity = request.form.get('quantity')
        project_id = request.form.get('project_id1', type=int)
        do_number = request.form.get('do_number')
        sub_item = request.form.get('sub_item')

        if 'action' in request.form and request.form['action'] == 'project_do_edit':

            if 'sub_item' in request.form:
                sub_item = request.form.get('sub_item')
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            else:
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity) VALUES (?, ?, ?, ?, ?)", (project_id, do_number, item, uom, quantity))

            # Fetch items after adding to display in the template
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()

            return render_template('admin_templates/purchase/purchase_po_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do)

        elif 'action' in request.form and request.form['action'] == 'add_sub_item':
            sub_item = request.form.get('sub_item')
            cursor = db.cursor()
            cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            cursor.execute("SELECT * FROM po_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()
            return render_template('admin_templates/purchase/purchase_po_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(item=item, uom=uom, quantity=quantity, sub_item=sub_item),created_do=created_do)

    return render_template('admin_templates/purchase/purchase_po_edit.html',current_date=formatted_date,enquiries_details=enquiries_details,is_pm=is_pm, department_code=department_code,items=items,
                          do_number_variable=do_number_variable, user=user, project_id=project_id,project_details=project_details,form_data=dict(),created_po=created_po)

@app.route('/delete_pur_po/<int:poid>', methods=["GET", "POST"])
@login_required
def delete_pur_po(poid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM created_po WHERE id = ?', [poid])
        db.commit()
        return redirect(url_for('purchase_po'))
    return render_template('purchase_po.html', user=user)

@app.route('/delete_pur_po_item/<int:id>', methods=["GET", "POST"])
@login_required
def delete_pur_po_item(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute("DELETE FROM temp_po_items WHERE id = ?", (id,))
        db.commit()
        return redirect(url_for('purchase_po'))
    return render_template('purchase_po.html', user=user)


##--------------------------------------------------------ADMIN------------------------------------------------------------------------------------------------------------------

@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    active_tab = 'dashboard'
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Query to get the total count of all projects
    total_projects_query = 'SELECT COUNT(*) FROM projects'
    total_projects = db.execute(total_projects_query).fetchone()[0]


    total_eq_query = 'SELECT COUNT(*) FROM enquiries'
    total_eqs = db.execute(total_eq_query).fetchone()[0]


    leaves_on_current_day_query = """SELECT COUNT(DISTINCT employeeID) AS number_of_employees FROM leaves WHERE STRFTIME('%Y-%m-%d', leave_date) = DATE('now')"""
    leaves_on_current_day = db.execute(leaves_on_current_day_query).fetchone()[0]

    leaves_data_query = """ SELECT employeeID, leave_type FROM leaves WHERE STRFTIME('%Y-%m-%d', leave_date) = DATE('now')"""
    leaves_data = db.execute(leaves_data_query).fetchall()

    # Query to get the total number of users
    total_users_query = 'SELECT COUNT(*) FROM admin_user'
    total_users = db.execute(total_users_query).fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
    PR_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_pr")
    PR_count = cursor.fetchone()[0]
    Q4 = """ SELECT project_id, created_by FROM created_pr WHERE status != 'Processed'"""
    pr_data = db.execute(Q4).fetchall()
    # Query to get the total count of all claims
    total_claims_query = 'SELECT COUNT(*) FROM claims'
    total_claims = db.execute(total_claims_query).fetchone()[0]

    Q1 = """ SELECT claim_by, claim_Total FROM claims WHERE status != 'Approved'"""
    claim_data = db.execute(Q1).fetchall()

    # Query to get the number of claims where the status is not approved
    unapproved_claims_query = "SELECT COUNT(*) FROM claims WHERE status != 'Approved'"
    unapproved_claims = db.execute(unapproved_claims_query).fetchone()[0]


    # Query to get the total count of all claims
    ttotal_expensess_query = 'SELECT COUNT(*) FROM Expenses'
    total_expenses = db.execute(ttotal_expensess_query).fetchone()[0]

    # Query to get the number of claims where the status is not approved
    unapproved_expenses_query = "SELECT COUNT(*) FROM Expenses WHERE status != 'Approved'"
    unapproved_expenses = db.execute(unapproved_expenses_query).fetchone()[0]

    Q2 = """ SELECT claim_by, claim_Total FROM Expenses WHERE status != 'Approved'"""
    expense_data = db.execute(Q2).fetchall()

    cursor.execute("SELECT COUNT(*) FROM created_po WHERE status != 'Closed' ")
    Po_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_po")
    Po_count = cursor.fetchone()[0]
    Q3 = """ SELECT project_id, created_by FROM created_po WHERE status == 'Issued'"""
    po_data = db.execute(Q3).fetchall()

    status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
    totalstatus = db.execute(status_query)
    status_counts = dict(totalstatus.fetchall())

    ordered_status_values = [0, 0, 0, 0, 0]  # Initialize with zeros
    custom_status_order = ['Open', 'Design', 'Install', 'Testing', 'Closed']

    enq_query = 'SELECT status, COUNT(*) AS count FROM enquiries GROUP BY status'
    totalenq = db.execute(enq_query)
    enq_counts = dict(totalenq.fetchall())

    userqq = 'SELECT department_code, COUNT(*) AS count FROM admin_user GROUP BY department_code'
    totalqu = db.execute(userqq)
    user_count = dict(totalqu.fetchall())


    if total_projects > 0:
        ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]
        status_counts = { 'Open': ordered_status_values[0], 'Build': ordered_status_values[1], 'Install': ordered_status_values[2], 'Testing': ordered_status_values[3],
            'Closed': ordered_status_values[4], 'Total Projects': total_projects }

    return render_template('admin_templates/admin/index.html',user=user,active_tab=active_tab,department_code=department_code,is_pm=is_pm,total_projects=total_projects,status_counts=status_counts,
                          PR_count=PR_count,PR_pending=PR_pending,total_users=total_users,leaves_on_current_day=leaves_on_current_day,total_eqs=total_eqs,total_claims=total_claims,enq_counts=enq_counts,
                          user_count=user_count,Po_pending=Po_pending,Po_count=Po_count, total_expenses=total_expenses, unapproved_expenses=unapproved_expenses,unapproved_claims=unapproved_claims,
                          pr_data=pr_data,po_data=po_data,expense_data=expense_data,claim_data=claim_data,leaves_data=leaves_data)

@app.route('/admin_add_project', methods=["POST", "GET"])
@login_required
def admin_add_project():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    active_tab = 'add_new'
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    message = ''  # Initialize an empty message
    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC ')
    project_ids = [row[0] for row in cursor.fetchall()]
    cursor = db.execute('SELECT * FROM cost_center ORDER BY id DESC')
    cost_center = cursor.fetchall()
    cursor = db.execute('SELECT * FROM industry ORDER BY id DESC')
    industry_list = cursor.fetchall()
    cursor = db.execute('SELECT * FROM vehicle ORDER BY id DESC')
    Vehicle_list = cursor.fetchall()

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

        db = get_database()

        try:
            cursor = db.cursor()
            cursor.execute('SELECT department_code FROM admin_user WHERE username = ?', [pm])
            result = cursor.fetchone()

            if result:
                department_code = result[0]
                db.execute('INSERT INTO projects (id, client, project_name, start_time, end_time, pm_status, pe_status, status,po_number, pm, pe,po_value,budget,billing_address,delivery_address,type ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                           [projectId, client, projectName, startTime, endTime, 1, 1, status,po_number, pm, pe,po_value,budget,billing_address,delivery_address,type])
                db.commit()
                flash(f"Project ' {projectId} ' is successfully added.", 'success')

            else:
                flash(f"The selected project manager ' {pm} ' does not exist. Please select a valid project manager.", 'error')

        except sqlite3.IntegrityError:
            flash(f"Project ID ' {projectId} ' already exists. Please provide a unique ID.", 'error')

    return render_template('admin_templates/admin/admin_add_project.html',project_ids=project_ids, user=user,cost_center=cost_center, usernames=usernames, active_tab=active_tab,
                           Vehicle_list=Vehicle_list,industry_list=industry_list,message=message)

@app.route('/admin_add_employee', methods=["POST", "GET"])
@login_required
def admin_add_employee():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    show = None

    if request.method == "POST":
        button_value = request.form.get('submit')
        Delete_Course = request.form.get('Delete_Course')
        Delete_industry = request.form.get('Delete_industry')
        Delete_Vehicle = request.form.get('Delete_Vehicle')

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

        if button_value == "add_cost_center":
            expenses_code = request.form['Expenses_Code']
            expenses_name = request.form['Expenses_Name']
            cursor.execute('SELECT * FROM cost_center WHERE code = ?', (expenses_code,))
            existing_code = cursor.fetchone()
            if existing_code:
                flash('Code already exists!', 'code_exits')
            else:
                cursor.execute('INSERT INTO cost_center (code, expenses_name) VALUES (?, ?)', (expenses_code, expenses_name))
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
            try:
                db.execute('INSERT INTO admin_user (name, username, department_code, register, rate_per_hour) VALUES (?, ?, ?, ?, ?)',
                           (name, username, department_code, register, rate_per_hour))
                db.commit()

                return redirect(url_for('admin_add_employee'))
            except sqlite3.IntegrityError:
                error = f"Employee ID '{username}' already exists. Please provide a unique ID."

    cursor = db.execute('SELECT * FROM cost_center ORDER BY id DESC')
    cost_center = cursor.fetchall()
    cursor = db.execute('SELECT * FROM industry ORDER BY id DESC')
    industry_list = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.execute('SELECT * FROM vehicle ORDER BY id DESC')
    Vehicle_list = cursor.fetchall()

    return render_template('admin_templates/admin/admin_add_project.html',show=show, Vehicle_list=Vehicle_list, cost_center=cost_center,industry_list=industry_list,user=user,department_code=department_code)



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

@app.route('/employee_search', methods=['POST'])
@login_required
def employee_search():
    name_or_code = request.form.get('name_or_code')
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]

    try:
        # Try to convert name_or_code to an integer
        code_as_int = int(name_or_code)

        if 1000 <= code_as_int <= 1050:
            # Execute this command if name_or_code is between 1000 to 1050
            cursor.execute("SELECT id, name, username, department_code, rate_per_hour, register FROM admin_user WHERE department_code = ?", (code_as_int,))
            admin_users = cursor.fetchall()
        else:
            # Execute this command for other cases
            cursor.execute("SELECT id, name, username, department_code, rate_per_hour, register FROM admin_user WHERE username = ?", (name_or_code,))
            admin_users = cursor.fetchall()

    except ValueError:
        # Handle the case where name_or_code is not a valid integer
        # Execute this command for other cases
        cursor.execute("SELECT id, name, username, department_code, rate_per_hour, register FROM admin_user WHERE username = ?", (name_or_code,))
        admin_users = cursor.fetchall()

    return render_template('admin_templates/admin/admin_view_all_employee_list.html', user=user, admin_users=admin_users, department_code=department_code,usernames=usernames)

@app.route('/admin_view_all_employee_list', methods=['GET', 'POST'])
@login_required
def admin_view_all_employee_list():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, username, department_code, rate_per_hour, register FROM admin_user")
    admin_users = cursor.fetchall()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    return render_template('admin_templates/admin/admin_view_all_employee_list.html', user=user, admin_users=admin_users,department_code=department_code,usernames = usernames)

@app.route('/edit_client/<int:client_id>', methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    print("sairammmmmm.........................")
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username( user['name'])

    if request.method == "POST":
        client = request.form['client']
        client_address = request.form['client_address']
        site = request.form['site']
        site_address = request.form['site_address']
        name = request.form['name']
        contact = request.form['contact']

        try:
            db.execute('UPDATE client_details SET client=?, client_address=?, site=?, site_address=?, name=?, contact=? WHERE id=?',
                       [client, client_address, site, site_address, name, contact, client_id])
            db.commit()
            flash(f"Client details for ID {client_id} are successfully updated.", 'success')
            return redirect(url_for('client_details'))

        except sqlite3.IntegrityError:
            flash("Failed to update client details. Please try again.", 'error')

        cursor = db.execute('SELECT * FROM client_details')
        client_details = cursor.fetchall()
        return render_template('admin_templates/admin/client_details.html', user=user,client_details=client_details,department_code=department_code)


    # Fetch client details for the specified ID
    cursor = db.execute('SELECT * FROM client_details WHERE id=?', [client_id])
    cli = cursor.fetchone()
    cursor = db.execute('SELECT * FROM client_details')
    client_details = cursor.fetchall()

    return render_template('admin_templates/admin/edit_client.html', user=user, cli =cli,client_details=client_details,department_code=department_code)

@app.route('/admin_leaves', methods=["POST", "GET"])
@login_required
def admin_leaves():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    cursor = db.execute('SELECT * FROM admin_leave_allocation')
    leaves_data = cursor.fetchall()
    # Get the current year
    current_year = datetime.now().year
    # Modify the query to filter data for the current year
    cursor.execute('SELECT * FROM public_holidays WHERE strftime("%Y", date) = ?', (str(current_year),))
    # Fetch the data
    holidays_data = cursor.fetchall()
    public_holidays_count = len(holidays_data)
    # cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (public_holidays_count,))

    # if request.method == "POST":
    if 'add_or_save' in request.form:
        EmployeeID = request.form['employee_id']
        Madical = request.form['Madical']
        Casual = request.form['Casual']
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
            update_query = ''' UPDATE admin_leave_allocation SET Madical = ?, Casual = ?, Annual = ?, Maternity = ?, Paternity = ?, Public=? WHERE EmployeeID = ?'''
            db.execute(update_query, (Madical, Casual, Annual, Maternity, Paternity,holiday_count, EmployeeID))
            cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
        else:
            # EmployeeID does not exist, insert a new row
            insert_query = '''INSERT INTO admin_leave_allocation (EmployeeID, Madical, Casual, Annual, Maternity, Paternity, Public) VALUES (?, ?, ?, ?, ?, ?, ?)'''
            db.execute(insert_query, (EmployeeID, Madical, Casual, Annual, Maternity, Paternity, holiday_count))
            cursor.execute('UPDATE admin_leave_allocation SET Public = ?', (holiday_count,))
        db.commit()

        cursor = db.execute('SELECT * FROM admin_leave_allocation')
        leaves_data = cursor.fetchall()

        return render_template('admin_templates/admin/admin_leaves.html', user=user, usernames=usernames,leaves_data=leaves_data,holidays_data=holidays_data)

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
        cursor = db.execute('SELECT * FROM admin_leave_allocation')
        leaves_data = cursor.fetchall()
        db.commit()
        return render_template('admin_templates/admin/admin_leaves.html', user=user, usernames=usernames,leaves_data=leaves_data,holidays_data=holidays_data)

    elif 'get_data' in request.form:


        EmployeeID = request.form['employee_id1']
        leave_types = ['Madical', 'Casual', 'Annual', 'Maternity', 'Paternity']
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
            used_dict['Madical'] = used_dict.pop('Medical')
        print("............used_dict............\n",used_dict)

        table_rows = []
        # Iterate through leave types and populate the table
        for leave_type in eligibility_dict:
            eligibility = eligibility_dict.get(leave_type, 0)
            used = used_dict.get(leave_type, 0)
            left = eligibility - used
            # Append a tuple representing a table row
            table_rows.append((leave_type, eligibility, used, left))
        table_rows = [(leave_type.replace('Madical', 'Medical'), eligibility, used, left) for leave_type, eligibility, used, left in table_rows]
        print("............table_rows............\n",table_rows)
        return render_template('admin_templates/admin/admin_leaves.html', user=user, usernames=usernames,leaves_data=leaves_data,holidays_data=holidays_data,table_rows=table_rows,EmployeeID=EmployeeID)

    return render_template('admin_templates/admin/admin_leaves.html', user=user, usernames=usernames,leaves_data=leaves_data,holidays_data=holidays_data)

@app.route('/edit_leaves', methods=["POST", "GET"])
@login_required
def edit_leaves():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    department_code = get_department_code_by_username( user['name'])
    leaves_data = None


    if request.method == "POST":
        # Get the form data
        employee_id = request.form.get('employee_id')
        start_date  = request.form.get('start_date')
        end_date    = request.form.get('end_date')

        print("...........................",employee_id)
        print("...........................",start_date)
        print("...........................",end_date)

        if employee_id and start_date and end_date:
            # If employee_id, start_date, and end_date are provided, fetch data for that employee within the specified date range
            cursor.execute("SELECT * FROM leaves WHERE employeeID = ? AND leave_date BETWEEN ? AND ?", (employee_id, start_date, end_date))
            leaves_data = cursor.fetchall()
        elif employee_id and start_date:
            # If both employee_id and start_date are provided, fetch data for that employee on the specified start_date
            cursor.execute("SELECT * FROM leaves WHERE employeeID = ? AND leave_date = ?", (employee_id, start_date))
            leaves_data = cursor.fetchall()

        elif employee_id:
            # If employee_id is provided, fetch all data for that employee
            cursor.execute("SELECT * FROM leaves WHERE employeeID = ?", (employee_id,))
            leaves_data = cursor.fetchall()
        else:
            # If no conditions are met, fetch all data
            cursor.execute("SELECT * FROM leaves")
            leaves_data = cursor.fetchall()

        print("...............leaves........",leaves_data)
        return render_template('admin_templates/admin/edit_leaves.html', user=user, usernames=usernames,department_code=department_code,leaves_data=leaves_data)




    return render_template('admin_templates/admin/edit_leaves.html', user=user, usernames=usernames,department_code=department_code,leaves_data=leaves_data)

from flask import request

@app.route('/deleteleave/<int:userid>', methods=["GET"])
@login_required
def deleteleave(userid):
    db = get_database()
    cursor = db.cursor()

    # Get the employeeID, leave_type, and leave_date from the leaves table
    cursor.execute('SELECT employeeID, leave_type FROM leaves WHERE id = ?', (userid,))
    result = cursor.fetchone()
    if result:
        employeeID, leave_type = result

        # Check if the leave_type column exists in admin_leave_allocation table
        cursor.execute("PRAGMA table_info(admin_leave_allocation)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]

        if leave_type in column_names:
            # Increment the leave count for the specified leave_type in admin_leave_allocation table
            cursor.execute(f'UPDATE admin_leave_allocation SET {leave_type} = {leave_type} + 1 WHERE EmployeeID = ?', (employeeID,))
        else:
            # If the leave_type column does not exist, create it and set its value to 1
            cursor.execute(f'ALTER TABLE admin_leave_allocation ADD COLUMN {leave_type} INT DEFAULT 1')

        db.commit()

        # Delete the leave record from the leaves table
        cursor.execute('DELETE FROM leaves WHERE id = ?', (userid,))
        db.commit()

    return redirect(url_for('edit_leaves'))

@app.route('/delete_holiday/<int:id>', methods=['GET'])
@login_required
def delete_holiday(id):
    db = get_database()
    cursor = db.cursor()
    current_year = datetime.now().year
    # Delete the row with the specified id
    cursor.execute('DELETE FROM public_holidays WHERE id = ?', (id,))
    cursor.execute('UPDATE admin_leave_allocation SET Public = Public - 1 ')

    db.commit()
    # Redirect to the page that displays the table
    return redirect(url_for('admin_leaves'))

@app.route('/delete_employee_leave_data/<int:id>', methods=['GET'])
@login_required
def delete_employee_leave_data(id):
    db = get_database()
    cursor = db.cursor()
    # Delete the row with the specified id
    cursor.execute('DELETE FROM admin_leave_allocation WHERE id = ?', (id,))
    db.commit()
    # Redirect to the page that displays the table
    return redirect(url_for('admin_leaves'))

@app.route('/get_enquiry_details', methods=['POST'])
@login_required
def get_enquiry_details():
    # Retrieve project ID from the AJAX request
    project_id = request.form.get('project_id')
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT Client, Name,EstimateValue FROM enquiries WHERE EnquiryNumber = ?', [project_id])
    result = cursor.fetchone()
    print(".............",result[0],"..................",result[1],"..................",result[2])

    # Return the data as JSON
    return jsonify({'client': result[0], 'projectName': result[1], 'po_value': result[2]})


@app.route('/deleteuser/<int:userid>', methods = ["GET", "POST"])
@login_required
def deleteuser(userid):
    # print("..................name.......................",username)
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        dbuser_cur = db.execute('SELECT username FROM admin_user WHERE id = ?', [userid,])
        existing_username = dbuser_cur.fetchone()[0]
        db.execute('DELETE FROM admin_user WHERE id = ?', (userid,))
        db.execute('delete from users where name = ?', (existing_username,))
        db.commit()
        return redirect(url_for('admin_view_all_employee_list'))
    return render_template('admin_view_all_employee_list.html', user = user)

@app.route('/fetchuser/<int:userid>/<username>')
@login_required
def fetchuser(userid, username):
    user = get_current_user()
    db = get_database()
    pro_cur = db.execute('select * from admin_user where id = ?', [userid])
    single_pro = pro_cur.fetchone()
    # print("...................",single_pro['register'])
    passw =  db.execute('SELECT password FROM users WHERE name = ?', (username,))
    password = passw.fetchone()

    if password:
        retrieved_password = password[0]
    else:
        retrieved_password = None

    db.commit()
    return render_template('admin_templates/admin/admin_editing_employee.html', user=user, single_pro=single_pro, password=retrieved_password)

@app.route('/edituser', methods = ["GET", "POST"])
@login_required
def edituser():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    if request.method == 'POST':
        userid = request.form['id']
        name = request.form['name']
        username = request.form['username']
        rate_per_hour = request.form['rate_per_hour']
        department_code = request.form['department_code']
        register = request.form['register']

        db = get_database()
        db.execute('UPDATE admin_user SET id=?, name=?, username=?, department_code=?, register=?, rate_per_hour=?  WHERE id=?',[userid, name, username, department_code, register,rate_per_hour,userid])
        db.commit()
        return redirect(url_for('admin_view_all_employee_list'))

    return render_template('admin_templates/admin/admin_editing_employee.html', user=user, userid=userid)

@app.route('/admin_claims', methods=["POST", "GET"])
@login_required
def admin_claims():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    # Select rows with status "open" for the last two months ordered by descending ID
    cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
    # Select rows with status "approved" for the last two months ordered by descending ID
    cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
    # Fetch the results
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    # Combine the results
    claims = open_claims + approved_claims

    if request.method == 'POST':

        action = request.form.get('action')
        if 'All_claims' in request.form:
            all_claims_cur = db.execute("SELECT * FROM claims ORDER BY id DESC;")
            all_claims = all_claims_cur.fetchall()
            return render_template('admin_templates/admin/all_claims.html',all_claims=all_claims, user=user, department_code=department_code)


        if 'Delete' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in claimdata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM claims WHERE claim_id = ?', (claim_id,))
                    db.execute('DELETE FROM claimed_items WHERE claim_no = ?', [claim_id])
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
        # Redirect to the original page or a different page as needed
        return redirect(url_for('admin_claims'))


    return render_template('admin_templates/admin/admin_claims.html',claims=claims, user = user,department_code=department_code)

@app.route('/view_claimitems', methods=["POST", "GET"])
@login_required
def view_claimitems():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    claim_no = request.args.get('no')

    # cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC")
    # cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC")
    # Fetch the results
    # open_claims = cursor_open.fetchall()
    # approved_claims = cursor_approved.fetchall()
    # Combine the results
    # all_claims = open_claims + approved_claims

    claim_no = request.args.get('no')

    cursor = db.execute('SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
    claim_items = cursor.fetchall()

    all_claims_cur = db.execute("SELECT * FROM claims ORDER BY id DESC;")
    all_claims = all_claims_cur.fetchall()
    return render_template('admin_templates/admin/all_claims.html',all_claims=all_claims, user=user, department_code=department_code, claim_items=claim_items)

@app.route('/view_expensesitems', methods=["POST", "GET"])
@login_required
def view_expensesitems():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    claim_no = request.args.get('no')

    claim_no = request.args.get('no')

    cursor = db.execute('SELECT * FROM expences_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
    claim_items = cursor.fetchall()

    all_claims_cur = db.execute("SELECT * FROM Expenses ORDER BY id DESC;")
    all_claims = all_claims_cur.fetchall()
    visiblity = 'view_all_expenses'
    return render_template('admin_templates/admin/admin_expenses.html',visiblity=visiblity,all_claims=all_claims, user=user, department_code=department_code, claim_items=claim_items)

@app.route('/edit_claims', methods=["POST", "GET"])
@login_required
def edit_claims():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])

    if request.method == 'GET':
        claim_no = request.args.get('no')

        cursor = db.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_no,))
        claim_details = cursor.fetchone()
        # Select rows with status "open" for the last two months ordered by descending ID
        cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
        # Select rows with status "approved" for the last two months ordered by descending ID
        cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
        # Fetch the results
        open_claims = cursor_open.fetchall()
        approved_claims = cursor_approved.fetchall()
        # Combine the results
        claims = open_claims + approved_claims
        cursor = db.execute('SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
        claim_items = cursor.fetchall()
        return render_template('admin_templates/admin/admin_claimedit.html', claim_no=claim_no,claims=claims, claim_details=claim_details, user=user, department_code=department_code, claim_items=claim_items)

    elif request.method == 'POST':

        action = request.form.get('action')

        if action == 'update_claim':
            # print('sairam')
            id = request.form.get('claim_no')
            claim_id = request.form.get('claim_id')
            claim_Total = request.form.get('claim_Total')
            Reference_Code = request.form.get('Reference_Code')
            status = request.form.get('status')
            Approvedby = request.form.get('Approvedby')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            Edit_status = request.form.get('Edit_status')
            # print("............Edit_status.............",Edit_status)

            # Update the claims table
            db.execute('UPDATE claims SET claim_id = ?, claim_Total = ?, Reference_Code = ?,Edit_status = ?, status = ?, approved_by = ?, approved_date = ?, comments = ?, last_update = CURRENT_DATE WHERE claim_id = ?',
                       (claim_id, claim_Total, Reference_Code, Edit_status, status, Approvedby, Approved_date, Comments, id))
            db.commit()
            # Select rows with status "open" for the last two months ordered by descending ID
            cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
            # Select rows with status "approved" for the last two months ordered by descending ID
            cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
            # Fetch the results
            open_claims = cursor_open.fetchall()
            approved_claims = cursor_approved.fetchall()
            # Combine the results
            claims = open_claims + approved_claims
            return render_template('admin_templates/admin/admin_claims.html',claims=claims, user=user, department_code=department_code)

        if action == 'approve_claim':
            # print('approve sairam')
            id = request.form.get('claim_no')
            claim_id = request.form.get('claim_id')
            claim_Total = request.form.get('claim_Total')
            Reference_Code = request.form.get('Reference_Code')
            status = 'Approved'
            Approvedby = request.form.get('Approvedby')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            cursor = db.execute('SELECT projectid,Sub_Category_code, claim_by,total FROM claimed_items WHERE claim_no = ?', (claim_id,))
            temp_claim_items = cursor.fetchall()

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

            db.execute('UPDATE claims SET claim_id = ?, claim_Total = ?, Reference_Code = ?, status = ?, approved_by = ?, approved_date = ?, comments = ?, last_update = CURRENT_DATE WHERE claim_id = ?',
                       (claim_id, claim_Total, Reference_Code, status, Approvedby, Approved_date, Comments, id))


            user_cur = db.execute('SELECT name FROM admin_user WHERE username = ?', (claim_by,))
            mail_to_row = user_cur.fetchone()

            # Ensure that an email was found for the user
            if mail_to_row:
                mail_to = mail_to_row['name']
                # print(".......mail_to............", mail_to)

                # Sending the leave notification email
                send_claims_notification(mail_to,claim_by, claim_id, status)
                # send_leaves_notification(mail_to, leave_details)
            else:
                print(f"No email found for user: {claim_by}")

            # send_claims_notification(user['email'],user, claim_id, status)

            # Select rows with status "open" for the last two months ordered by descending ID
            cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
            # Select rows with status "approved" for the last two months ordered by descending ID
            cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
            # Fetch the results
            open_claims = cursor_open.fetchall()
            approved_claims = cursor_approved.fetchall()
            # Combine the results
            claims = open_claims + approved_claims

            db.commit()
            return render_template('admin_templates/admin/admin_claims.html',claims=claims, user=user, department_code=department_code)

        if 'Delete' in request.form:
            # print("...................in the delete form")
            claimdata = request.form.getlist('claimdata[]')
            # print("........claimdata............",claimdata)
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in claimdata:
                    # print("...............id............", claim_str)
                    claim_id = claim_str.split('|')[0]
                    # print("...............id............", claim_id)
                    cursor.execute('DELETE FROM claims WHERE claim_id = ?', (claim_id,))

                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            # Redirect to the original page or a different page as needed
            return redirect(url_for('admin_claims'))

        if 'All_claims' in request.form:
            all_claims_cur = db.execute("SELECT * FROM claims ORDER BY id DESC;")
            all_claims = all_claims_cur.fetchall()
            return render_template('admin_templates/admin/all_claims.html',all_claims=all_claims, user=user, department_code=department_code)


    # Select rows with status "open" for the last two months ordered by descending ID
    # cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
    cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")

    # Select rows with status "approved" for the last two months ordered by descending ID
    cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
    # Fetch the results
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    # Combine the results
    claims = open_claims + approved_claims
    claim_no = request.args.get('no')
    cursor = db.execute("SELECT * FROM claims WHERE id = ?", (claim_no,))
    claim_details = cursor.fetchone()
    return render_template('admin_templates/admin/admin_claimedit.html', claims=claims, claim_details=claim_details, user=user, department_code=department_code)

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


@app.route('/deleteclaim/<int:claimid>', methods=["GET", "POST"])
@login_required
def deleteclaim(claimid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        cursor = db.execute("SELECT claim_id FROM claims WHERE id = ?", (claimid,))
        claim_no = cursor.fetchone()[0]
        db.execute('DELETE FROM claimed_items WHERE claim_no = ?', [claim_no])
        db.execute('DELETE FROM claims WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('admin_claims'))
    return render_template('admin_claims.html', user=user)

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
    # Select rows with status "open" for the last two months ordered by descending ID
    cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
    # Select rows with status "approved" for the last two months ordered by descending ID
    cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
    # Fetch the results
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    # Combine the results
    claims = open_claims + approved_claims

    all_claims_cur = db.execute("SELECT * FROM Expenses ORDER BY id DESC;")
    all_claims = all_claims_cur.fetchall()

    if request.method == 'POST':

        action = request.form.get('action')

        if 'Delete' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in claimdata:
                    claim_id = claim_str.split('|')[0]
                    cursor.execute('DELETE FROM Expenses WHERE claim_id = ?', (claim_id,))
                    db.execute('DELETE FROM expences_items WHERE claim_no = ?', [claim_id])
                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
        # Redirect to the original page or a different page as needed
        return redirect(url_for('admin_expenses'))


    return render_template('admin_templates/admin/admin_expenses.html',claims=claims, user = user,department_code=department_code,all_claims=all_claims)

@app.route('/edit_expenses', methods=["POST", "GET"])
@login_required
def edit_expenses():
    print(".......in expenses edit........")
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])

    if request.method == 'GET':
        claim_no = request.args.get('no')
        print("......calim_no..............",claim_no)

        cursor = db.execute("SELECT * FROM Expenses WHERE claim_id = ?", (claim_no,))
        claim_details = cursor.fetchone()
        # Select rows with status "open" for the last two months ordered by descending ID
        cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
        # Select rows with status "approved" for the last two months ordered by descending ID
        cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
        # Fetch the results
        open_claims = cursor_open.fetchall()
        approved_claims = cursor_approved.fetchall()
        # Combine the results
        claims = open_claims + approved_claims
        cursor = db.execute('SELECT * FROM expences_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
        claim_items = cursor.fetchall()
        print(".......in expenses edit........claim_no.........",claim_no,claim_details)
        visiblity = 'approve_claims'
        return render_template('admin_templates/admin/edit_expenses.html', visiblity=visiblity, claim_no=claim_no,claims=claims, claim_details=claim_details, user=user, department_code=department_code, claim_items=claim_items)

    elif request.method == 'POST':

        action = request.form.get('action')

        if action == 'update_claim':
            print('sairam')
            id = request.form.get('claim_no')
            claim_id = request.form.get('claim_id')
            claim_Total = request.form.get('claim_Total')
            Reference_Code = request.form.get('Reference_Code')
            status = request.form.get('status')
            Approvedby = request.form.get('Approvedby')
            Approved_date = request.form.get('Approved_date')
            Comments = request.form.get('Comments')
            Edit_status = request.form.get('Edit_status')
            print("............Edit_status.............",Edit_status)

            # Update the claims table
            db.execute('UPDATE Expenses SET claim_id = ?, claim_Total = ?, Reference_Code = ?,Edit_status = ?, status = ?, approved_by = ?, approved_date = ?, comments = ?, last_update = CURRENT_DATE WHERE claim_id = ?',
                       (claim_id, claim_Total, Reference_Code, Edit_status, status, Approvedby, Approved_date, Comments, id))
            db.commit()
            # Select rows with status "open" for the last two months ordered by descending ID
            cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
            # Select rows with status "approved" for the last two months ordered by descending ID
            cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
            # Fetch the results
            open_claims = cursor_open.fetchall()
            approved_claims = cursor_approved.fetchall()
            # Combine the results
            claims = open_claims + approved_claims
            return render_template('admin_templates/admin/admin_expenses.html',claims=claims, user=user, department_code=department_code)

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

            print("............claim_by..............",claim_by)
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


            # Select rows with status "open" for the last two months ordered by descending ID
            cursor_open = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
            # Select rows with status "approved" for the last two months ordered by descending ID
            cursor_approved = db.execute("SELECT * FROM Expenses WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
            # Fetch the results
            open_claims = cursor_open.fetchall()
            approved_claims = cursor_approved.fetchall()
            # Combine the results
            claims = open_claims + approved_claims

            db.commit()
            return render_template('admin_templates/admin/admin_expenses.html',claims=claims, user=user, department_code=department_code)

        if 'Delete' in request.form:
            # print("...................in the delete form")
            claimdata = request.form.getlist('claimdata[]')
            # print("........claimdata............",claimdata)
            db = get_database()
            cursor = db.cursor()
            try:
            # Delete the selected claims from temp_claims
                for claim_str in claimdata:
                    # print("...............id............", claim_str)
                    claim_id = claim_str.split('|')[0]
                    # print("...............id............", claim_id)
                    cursor.execute('DELETE FROM Expenses WHERE claim_id = ?', (claim_id,))

                db.commit()
                flash('Selected claims deleted successfully.', 'success')

            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
            # Redirect to the original page or a different page as needed
            return redirect(url_for('admin_claims'))

        if 'All_claims' in request.form:
            all_claims_cur = db.execute("SELECT * FROM Expenses ORDER BY id DESC;")
            all_claims = all_claims_cur.fetchall()
            return render_template('admin_templates/admin/admin_expenses.html',all_claims=all_claims, user=user, department_code=department_code)


    # Select rows with status "open" for the last two months ordered by descending ID
    # cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")
    cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') ORDER BY id DESC;")

    # Select rows with status "approved" for the last two months ordered by descending ID
    cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' ORDER BY id DESC;")
    # Fetch the results
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    # Combine the results
    claims = open_claims + approved_claims
    claim_no = request.args.get('no')
    cursor = db.execute("SELECT * FROM claims WHERE id = ?", (claim_no,))
    claim_details = cursor.fetchone()
    print(".......in expenses edit........claim_no.........",claim_no,claim_details)
    return render_template('admin_templates/admin/admin_claimedit.html', claims=claims, claim_details=claim_details, user=user, department_code=department_code)


@app.route('/admin_pr', methods=["POST", "GET"])
@login_required
def admin_pr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    show = 'pr'

    if request.method == 'POST':
        PR_Approve = request.form.get('PR_Approve')
        PR_Issued =  request.form.get('PR_Issued')
        PR_Delete =  request.form.get('PR_Delete')
        PO_Print = request.form.get ('PO_Print')
        PO_Issued = request.form.get('PO_Issued')
        PO_Delete = request.form.get('PO_Delete')

        if PR_Approve:
            cursor.execute('UPDATE created_pr SET status = ? WHERE id = ?', ('Approved', PR_Approve))
            show = 'pr'

        if PR_Issued:
            cursor.execute('UPDATE created_pr SET status = ? WHERE id = ?', ('Processed', PR_Issued))
            cursor.execute('SELECT * FROM created_pr WHERE id = ?', (PR_Issued,))
            pr_details = cursor.fetchone()
            (id, PR_no, project_id, Supplier_Name, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery,
             Address_Line1, Address_Line2, Payment_Terms, Currency, status, total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,comments,approved_by) = pr_details
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

            cursor.execute('''INSERT INTO created_po (PO_no, project_id, Supplier_Name, phone_number, PO_Date, created_by, Quote_Ref, Expenses, Delivery, Address_Line1,
                           Address_Line2, Payment_Terms, Currency, status, total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,comments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            ( PO_no, project_id, Supplier_Name, phone_number, formatted_date, created_by, Quote_Ref, Expenses, Delivery,
                            Address_Line1, Address_Line2, Payment_Terms, Currency, 'Issued', total, Attn,Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time,comments))

            cursor.execute("SELECT * FROM pr_items WHERE pr_number = ? AND project_id = ?", (PR_no, project_id))
            temp_items = cursor.fetchall()

            # Insert fetched items into pr_items
            for item in temp_items:
                cursor.execute("INSERT INTO po_items (project_id, PO_number, Part_No, item, quantity, uom, Unit_Price, total, GST) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (item['project_id'], PO_no, item['Part_No'], item['item'], item['quantity'], item['uom'], item['Unit_Price'], item['total'],item['GST']))

                cursor.execute("SELECT 1 FROM manual_entry WHERE department_code = ? AND project_id = ?", (Expenses, project_id))
                existing_record = cursor.fetchone()
                total_sum = float(item['total'].replace(',', ''))
                if existing_record:
                    # Update the existing record
                    cursor.execute("UPDATE manual_entry SET added_cost = added_cost + ?, total = total + ? WHERE project_id = ? AND department_code = ?", ( total_sum, total_sum, project_id, Expenses))
                    print('updated',total_sum, project_id, Expenses)
                else:
                    # Insert a new record
                    cursor.execute("INSERT INTO manual_entry (project_id, department_code, cost, added_cost, total) VALUES (?, ?, ?, ?, ?)", (project_id, Expenses, total_sum, total_sum, total_sum))
                    print('inserted',total_sum, project_id, Expenses)
            show = 'pr'

        if PR_Delete:
            cursor.execute('DELETE FROM created_pr WHERE id = ?', (PR_Delete,))
            show = 'pr'

        if PO_Issued:
            cursor.execute('UPDATE created_po SET status = ? WHERE id = ?', ('Issued', PO_Issued))
            show = 'po'

        if PO_Delete:
            cursor.execute('DELETE FROM created_po WHERE id = ?', (PO_Delete,))
            show = 'po'

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

    cursor.execute('SELECT PR_no FROM created_pr')
    pr_nos = cursor.fetchall()

    # Iterate through each PR_no and check for corresponding items in pr_items
    for pr_no in pr_nos:
        cursor.execute('SELECT COUNT(*) FROM pr_items WHERE pr_number = ? ', (pr_no[0],))
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.execute('DELETE FROM created_pr WHERE PR_no = ? ', (pr_no[0],))

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
        rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
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
        rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Approved_by': Approved_by, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    # Convert rows to a pandas DataFrame
    grouped_df_pr = pd.DataFrame(rows)
    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
    PR_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_pr ")
    PR_count = cursor.fetchone()[0]

    #-------------------------------------------------------------------------------------------------------

    search_values = [0,0,'none']
    search_values1 = [0, 0, 'none']

    cursor.execute('SELECT PR_no FROM created_pr ORDER BY id DESC ')
    PR_Numbers = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT project_id FROM created_pr ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Expenses FROM created_pr ORDER BY id DESC')
    Expenses = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Supplier_Name FROM created_pr ORDER BY id DESC')
    Supplier_Names = [row[0] for row in cursor.fetchall()]

    db.commit()
    db.close()


    return render_template('admin_templates/admin/admin_pr.html', PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr, user=user,
                          search_values1=search_values1,show = show, PR_Numbers=PR_Numbers,project_ids=project_ids,Expenses=Expenses,Supplier_Names=Supplier_Names,search_values=search_values,department_code=department_code, is_pm=is_pm)

from datetime import datetime, timedelta
@app.route('/pr_search', methods=['GET', 'POST'])
@login_required
def pr_search():
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    if request.method == 'GET':

        PR_No = request.args.get('PR_No') if request.args.get('PR_No') else None
        selected_supplier_names = request.args.getlist('selected_supplier_names')
        selected_status = request.args.getlist('selected_checkboxes')
        selected_project_ids = request.args.getlist('selected_project_ids')
        selected_expenses = request.args.getlist('selected_expenses')

        search_values = [PR_No, 0, 0]
        search_values1 = [PR_No, 0, 0]
        db = get_database()
        cursor = db.cursor()

        # Construct the query based on the conditions
        query = 'SELECT * FROM created_pr WHERE 1=1'

        if PR_No is not None:
            query += f' AND PR_no = "{PR_No}"'
            selected_status = []
            selected_supplier_names = []
            selected_project_ids = []
            selected_expenses = []

        else:
            # Status condition
            if selected_status:
                status_condition = ' OR '.join([f"status = '{status_value}'" for status_value in selected_status])
                query += f' AND ({status_condition})'

            # Project ID condition
            if selected_project_ids:
                project_ids_condition = ' OR '.join([f"project_id = '{project_id}'" for project_id in selected_project_ids])
                query += f' AND ({project_ids_condition})'

            # Expenses condition
            if selected_expenses:
                expenses_condition = ' OR '.join([f"Expenses = '{expense}'" for expense in selected_expenses])
                query += f' AND ({expenses_condition})'

            # Supplier Name condition
            if selected_supplier_names:
                supplier_names_condition = ' OR '.join([f"Supplier_Name = '{supplier_name}'" for supplier_name in selected_supplier_names])
                query += f' AND ({supplier_names_condition})'

        # Order the data by id in descending order
        query += " ORDER BY id DESC"

        print(query)
        # Execute the query
        pro_cur = db.execute(query)
        created_pr = pro_cur.fetchall()

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
            rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
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
            rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                'Sub_DF': pd.DataFrame(sub_df_data) })

        # Convert rows to a pandas DataFrame
        grouped_df_pr = pd.DataFrame(rows)

        cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
        PR_pending = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM created_pr ")
        PR_count = cursor.fetchone()[0]


        cursor.execute('SELECT PR_no FROM created_pr ORDER BY id DESC')
        PR_Numbers = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT project_id FROM created_pr ORDER BY id DESC')
        project_ids = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Expenses FROM created_pr ORDER BY id DESC')
        Expenses = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Supplier_Name FROM created_pr ORDER BY id DESC')
        Supplier_Names = [row[0] for row in cursor.fetchall()]


        cursor.execute('SELECT PO_no FROM created_po ORDER BY id DESC')
        PO_Numbers = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT project_id FROM created_po ORDER BY id DESC')
        project_ids1 = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Expenses FROM created_po ORDER BY id DESC')
        Expenses1 = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Supplier_Name FROM created_po ORDER BY id DESC')
        Supplier_Names1 = [row[0] for row in cursor.fetchall()]


        print(".........................\n",grouped_df_pr)
        print("..............selected_status...........\n",selected_status)
        print(".............selected_expenses............\n",selected_expenses)
        print("..............selected_project_ids...........\n",selected_project_ids)
        print("..............selected_supplier_names...........\n",selected_supplier_names)
        print("..............PR_Numbers...........\n",PR_Numbers)
        show = 'pr'
        # Example conversion to strings
        # selected_project_ids = [str(pid) for pid in selected_project_ids]
        selected_project_ids = [int(pid) for pid in selected_project_ids]

        selected_expenses = [int(pid) for pid in selected_expenses]


        return render_template('admin_templates/admin/admin_pr.html', search_values=search_values,selected_expenses=selected_expenses,selected_project_ids=selected_project_ids,selected_status=selected_status,
                            search_values1=search_values1, PR_Numbers = PR_Numbers, project_ids=project_ids, Expenses=Expenses, Supplier_Names=Supplier_Names,
                            PO_Numbers = PO_Numbers, project_ids1=project_ids1, Expenses1=Expenses1, Supplier_Names1=Supplier_Names1,show=show,selected_supplier_names=selected_supplier_names,
                            is_pm=is_pm, department_code=department_code, user=user,PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr,)

from datetime import datetime, timedelta
@app.route('/po_search', methods=['GET', 'POST'])
@login_required
def po_search():
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    if request.method == 'GET':

        PR_No = request.args.get('PO_No') if request.args.get('PO_No') else None
        selected_supplier_names1 = request.args.getlist('selected_supplier_names')
        selected_status1 = request.args.getlist('selected_checkboxes')
        selected_project_ids1 = request.args.getlist('selected_project_ids')
        selected_expenses1 = request.args.getlist('selected_expenses')

        search_values1 = [PR_No, 0, 0]
        search_values = [PR_No, 0, 0]
        db = get_database()
        cursor = db.cursor()

        # Construct the query based on the conditions
        query = 'SELECT * FROM created_po WHERE 1=1'

        if PR_No is not None:
            query += f' AND PO_no = "{PR_No}"'
            selected_status1 = []
            selected_supplier_names1 = []
            selected_project_ids1 = []
            selected_expenses1 = []

        else:
            # Status condition
            if selected_status1:
                status_condition = ' OR '.join([f"status = '{status_value}'" for status_value in selected_status1])
                query += f' AND ({status_condition})'

            # Project ID condition
            if selected_project_ids1:
                project_ids_condition = ' OR '.join([f"project_id = '{project_id}'" for project_id in selected_project_ids1])
                query += f' AND ({project_ids_condition})'

            # Expenses condition
            if selected_expenses1:
                expenses_condition = ' OR '.join([f"Expenses = '{expense}'" for expense in selected_expenses1])
                query += f' AND ({expenses_condition})'

            # Supplier Name condition
            if selected_supplier_names1:
                supplier_names_condition = ' OR '.join([f"Supplier_Name = '{supplier_name}'" for supplier_name in selected_supplier_names1])
                query += f' AND ({supplier_names_condition})'

        # Order the data by id in descending order
        query += " ORDER BY id DESC"

        print(query)
        # Execute the query
        pro_cur = db.execute(query)
        created_po = pro_cur.fetchall()

        cursor = db.execute('SELECT * FROM created_pr ORDER BY id DESC')
        created_pr = cursor.fetchall()
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
            rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
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
            rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                'Sub_DF': pd.DataFrame(sub_df_data) })

        # Convert rows to a pandas DataFrame
        grouped_df_pr = pd.DataFrame(rows)

        cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
        PR_pending = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM created_pr ")
        PR_count = cursor.fetchone()[0]


        cursor.execute('SELECT PR_no FROM created_pr ORDER BY id DESC')
        PR_Numbers = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT project_id FROM created_pr ORDER BY id DESC')
        project_ids = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Expenses FROM created_pr ORDER BY id DESC')
        Expenses = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Supplier_Name FROM created_pr ORDER BY id DESC')
        Supplier_Names = [row[0] for row in cursor.fetchall()]

        #------------------------------------------------------

        cursor.execute('SELECT PO_no FROM created_po ORDER BY id DESC')
        PO_Numbers = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT project_id FROM created_po ORDER BY id DESC')
        project_ids1 = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Expenses FROM created_po ORDER BY id DESC')
        Expenses1 = [row[0] for row in cursor.fetchall()]

        cursor.execute('SELECT DISTINCT Supplier_Name FROM created_po ORDER BY id DESC')
        Supplier_Names1 = [row[0] for row in cursor.fetchall()]

        print(".........................\n",grouped_df_pr)
        print("..............selected_status...........\n",selected_status1)
        print(".............selected_expenses............\n",selected_expenses1)
        print("..............selected_project_ids...........\n",selected_project_ids1)
        print("..............selected_supplier_names...........\n",selected_supplier_names1)
        print("..............PR_Numbers...........\n",PO_Numbers)
        show = 'pr'
        # Example conversion to strings
        # selected_project_ids = [str(pid) for pid in selected_project_ids]
        selected_project_ids1 = [int(pid) for pid in selected_project_ids1]

        selected_expenses1 = [int(pid) for pid in selected_expenses1]


        return render_template('admin_templates/admin/admin_pr.html', search_values=search_values,
                            search_values1=search_values1, selected_expenses1=selected_expenses1, selected_checkboxes1=selected_status1, selected_project_ids1=selected_project_ids1,
                            selected_supplier_names1=selected_supplier_names1, PR_Numbers = PR_Numbers, project_ids=project_ids, Expenses=Expenses, Supplier_Names=Supplier_Names,
                            PO_Numbers = PO_Numbers, project_ids1=project_ids1, Expenses1=Expenses1, Supplier_Names1=Supplier_Names1,show=show,
                            is_pm=is_pm, department_code=department_code, user=user,PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr,)



@app.route('/PR_PO_edit', defaults={'id': None}, methods=["POST", "GET"])
@app.route('/PR_PO_edit/<int:id>', methods=["POST", "GET"])
@login_required
def PR_PO_edit(id):

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
                flash('PO Header Updated successfully!', 'po_header_success')

                cursor.execute("SELECT * FROM created_po where PO_no = ?", (New_PO_no,))
                header_details = cursor.fetchone()
                cursor.execute('SELECT display_name FROM vendors_details')
                Supplier_Names = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute('SELECT username FROM admin_user')
                usernames = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute("SELECT * FROM po_items WHERE PO_number = ?", (New_PO_no,))
                pr_items = cursor.fetchall()
                db.commit()
                p = 2
                show = 'po'

                return render_template('admin_templates/admin/PR_PO_edit.html',project_id=project_id1,pr_items=pr_items,Supplier_Names=Supplier_Names,usernames=usernames,
                                 show = show,  p = p, New_PO_no=New_PO_no,user=user,department_code=department_code,header_details=header_details, is_pm=is_pm)

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
                    db.commit()
                    # Update the status of the PR
                    status = 'Approved' if department_code <= 1001 else 'Created'
                    cursor.execute("UPDATE created_po SET status = ? WHERE PO_no = ?", (status, PO_number))
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
                    rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
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
                    rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })

                # Convert rows to a pandas DataFrame
                grouped_df_pr = pd.DataFrame(rows)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr ")
                PR_count = cursor.fetchone()[0]

                db.commit()
                db.close()
                show = 'po'
                p = 2
                print('the we are going to the admn pr...............................')

                search_values = [0, 0, 0]
                search_values1 = [0, 0, 0]

                return render_template('admin_templates/admin/admin_pr.html', PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr, user=user, p = p,
                                   search_values=search_values, search_values1=search_values1, show = show, department_code=department_code, is_pm=is_pm)

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
        Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

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

        pattern = re.compile(r"(\d{4}-\d{4}-\d{4})(\((\d+)\))?$")
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

        return render_template('admin_templates/admin/PR_PO_edit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                          show = show, New_PO_no=New_PO_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

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
                print("................Old_PR_no..............",Old_PR_no)
                print("................New_PR_no..............",New_PR_no)
                print("................project_id..............",project_id)
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
                flash('PR Header Updated successfully!', 'pr_header_success')

                cursor.execute("SELECT * FROM created_pr where PR_no = ?", (New_PR_no,))
                header_details = cursor.fetchone()
                cursor.execute('SELECT display_name FROM vendors_details')
                Supplier_Names = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute('SELECT username FROM admin_user')
                usernames = sorted([row[0] for row in cursor.fetchall()])
                cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (New_PR_no,))
                pr_items = cursor.fetchall()
                db.commit()
                show = 'pr'
                p =1

                return render_template('admin_templates/admin/PR_PO_edit.html',project_id=project_id1,pr_items=pr_items,Supplier_Names=Supplier_Names,usernames=usernames,
                                   show = show, p = p, New_PR_no=New_PR_no,user=user,department_code=department_code,header_details=header_details, is_pm=is_pm)

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
                    status = 'Approved' if department_code <= 1001 else 'Created'
                    cursor.execute("UPDATE created_pr SET status = ? WHERE PR_no = ?", (status, pr_number))
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
                    rows1.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
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
                    rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                        'Sub_DF': pd.DataFrame(sub_df_data) })

                # Convert rows to a pandas DataFrame
                grouped_df_pr = pd.DataFrame(rows)
                cursor.execute("SELECT COUNT(*) FROM created_pr WHERE status != 'Processed' ")
                PR_pending = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM created_pr ")
                PR_count = cursor.fetchone()[0]

                db.commit()
                db.close()
                show = 'pr'
                p =1

                return render_template('admin_templates/admin/admin_pr.html', PR_pending=PR_pending, PR_count=PR_count,grouped_df_po=grouped_df_po, grouped_df_pr=grouped_df_pr, user=user,
                                       show = show, p = p, department_code=department_code, is_pm=is_pm)



        cursor.execute('SELECT display_name FROM vendors_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

        cursor.execute('SELECT username FROM admin_user')
        usernames = sorted([row[0] for row in cursor.fetchall()])

        cursor.execute("SELECT * FROM created_pr where id = ?", (id,))
        header_details = cursor.fetchone()
        print(".............id.........",id)
        cursor.execute("SELECT PR_no FROM created_pr where id = ?", (id,))
        prnumber = cursor.fetchone()[0]
        print(".............prnumber.........",prnumber)
        # Fetch pr_items associated with pr_number
        cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (prnumber,))
        pr_items = cursor.fetchall()
        parts = prnumber.split('-')
        if len(parts) == 3:
            project_id = parts[0]

        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d-%m-%y")

        pattern = re.compile(r"(\d{4}-\d{4}-\d{4})(\((\d+)\))?$")
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
            New_PR_no = "Invalid PR number format"

        print(".............project_id.........",project_id)
        show = 'pr'
        p =1

        return render_template('admin_templates/admin/PR_PO_edit.html', Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,p = p,
                           show =show, New_PR_no=New_PR_no, current_date = formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)


@app.route('/admin_po', methods=["POST", "GET"])
@login_required
def admin_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
    created_pr = cursor.fetchall()
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

        cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM po_items WHERE PO_number = ?', (pr_no,))
        items = cursor.fetchall()
        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
        total_price_sum = sum([float(item[4]) for item in items])
        # Append the main row to the rows list
        rows.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    # Convert rows to a pandas DataFrame
    grouped_df = pd.DataFrame(rows)
    # Display the DataFrame

    if request.method == 'POST':
        Print = request.form.get('Print')
        Issued = request.form.get('Issued')
        Delete = request.form.get('Delete')
        db = get_database()
        cursor = db.cursor()
        if Issued:
            cursor.execute('UPDATE created_po SET status = ? WHERE id = ?', ('Issued', Issued))
        if Delete:
            cursor.execute('DELETE FROM created_po WHERE id = ?', (Delete,))


        if Print:
            cursor.execute('SELECT PO_no FROM created_po WHERE id = ?', (Print,))
            PO_number = cursor.fetchone()
            cursor.execute('SELECT * FROM created_po WHERE id = ?', (Print,))
            po_details = cursor.fetchone()
            if po_details:
                column_names = [description[0] for description in cursor.description]
                po_dict = dict(zip(column_names, po_details))
                for key, value in po_dict.items():
                    print(f"{key}: {value}")
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

                # print("...............data_dict.../n",data_dict)
                total_sum = "{:,.2f}".format(total_sum)
                # print("...................Sum of total:.....", total_sum)

                pdf_filename = claim_to_po_pdf(data_dict, total_sum, po_details)
                if pdf_filename:
                    db.commit()
                    # Serve the PDF directly
                    return po_pdf_and_refresh(pdf_filename)

            else:
                print("No PO number found for the given ID:", Print)

        cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
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

            # Fetch items for the current PR from pr_items table
            cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM po_items WHERE po_number = ?', (pr_no,))
            items = cursor.fetchall()

            # Prepare aggregated values as a list of dictionaries (for sub_df)
            sub_df_data = []
            for item in items:
                sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
            total_price_sum = sum([float(item[4]) for item in items])
            # Append the main row to the rows list
            rows.append({ 'ID': pr_id,'PO_Date': pr_date, 'PO_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                'Sub_DF': pd.DataFrame(sub_df_data) })
        # Convert rows to a pandas DataFrame
        grouped_df = pd.DataFrame(rows)
        db.commit()
        db.close()
        # Redirect to PR view page after updating
        return render_template('admin_templates/admin/admin_po.html',grouped_df=grouped_df, user=user, department_code=department_code, is_pm=is_pm)

    # Optionally, return a template with the grouped_df passed as context
    return render_template('admin_templates/admin/admin_po.html',grouped_df=grouped_df, user=user, department_code=department_code, is_pm=is_pm)

def claim_to_po_pdf(data_dict, total_sum, po_details):
    db = get_database()
    cursor = db.cursor()

    # Create a buffer to hold the PDF content
    pdf_buffer = BytesIO()

    # Create a canvas and generate the PDF
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    c = po_pdf(c,data_dict, total_sum, po_details)
    c.setFillColorRGB(0, 0, 1)
    c.setFont("Helvetica", 16)
    c.showPage()
    c.save()


    pdf_filename = f"{po_details['PO_no']}.pdf"
    temp_dir = '/tmp'  # Temporary directory on the server
    pdf_path = os.path.join(temp_dir, pdf_filename)

    # Ensure the directory exists
    os.makedirs(temp_dir, exist_ok=True)


    try:
        with open(pdf_path, 'wb') as pdf_file:
            pdf_file.write(pdf_buffer.getvalue())
        print(f"PDF saved34534 successfully as {pdf_path}")
        return pdf_filename
    except Exception as e:
        print(f"Error saving PDF: {e}")

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor = db.execute('SELECT * FROM temp_claims')
    claims_data = cursor.fetchall()
    db.commit()

    # Render the template
    return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, user=user, claims_data=claims_data)

def po_pdf_hedder(c, po_details):
    c.translate(inch, inch)

    # Define a large font
    c.setFont("Helvetica", 10)

    # Centroid logo resized image
    image_path = 'templates/admin_templates/projects/ces.jpeg'
    image_width = 2  # Set the desired width in inches
    image_height = 0.3  # Set the desired height in inches
    # c.drawImage(image_path, 4.7 * inch, 9.3 * inch, width=image_width * inch, height=image_height * inch)

    # Centroid Address
    c.drawString(0.02 * inch, 9.5 * inch, "Centroid Engineering Solutions Pte Ltd")
    c.drawString(0.02 * inch, 9.3 * inch, "Co  Regn No: 201308058R")
    c.drawString(0.02 * inch, 9.1 * inch, "GST Regn No: 201308058R")
    c.drawString(0.02 * inch, 8.9 * inch, "11, Woodlands Close, #07-10")
    c.drawString(0.02 * inch, 8.7 * inch, "Singapore - 737853")

    # Delivery order
    c.setFont("Helvetica-Bold", 15)
    c.drawString(2.7 * inch, 8.7 * inch, 'PURCHASE ORDER')

    # Lines
    c.setFillColorRGB(0, 0, 0)  # Font colour
    c.line(0, 8.6 * inch, 6.8 * inch, 8.6 * inch)
    c.line(0, 7.5 * inch, 6.8 * inch, 7.5 * inch)
    c.line(0, 6.6 * inch, 6.8 * inch, 6.6 * inch)
    c.line(0, 6.3 * inch, 6.8 * inch, 6.3 * inch)

    c.line(0, 9.7 * inch, 6.8 * inch, 9.7 * inch)
    # c.line(0, 1.5 * inch, 6.8 * inch, 1.5 * inch)
    c.line(-0.3, -0.7 * inch, 6.8 * inch, -0.7 * inch)

    # c.line(4.6 * inch, 1.2 * inch, 6.8 * inch, 1.2 * inch) #three small lines
    # c.line(4.6 * inch, 0.9 * inch, 6.8 * inch, 0.9 * inch)
    # c.line(4.6 * inch, 0.6 * inch, 6.8 * inch, 0.6 * inch)
    c.line(0.0 * inch, 9.7 * inch, 0.0 * inch, -0.7 * inch)

    # c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, 1.5 * inch) # 6 horizontal lines
    # c.line(1.5 * inch, 6.6 * inch, 1.5 * inch, 1.5 * inch)
    # c.line(4.1 * inch, 6.6 * inch, 4.1 * inch, 1.5 * inch)
    # c.line(4.6 * inch, 6.6 * inch, 4.6 * inch, 0.6 * inch)
    # c.line(5.1 * inch, 6.6 * inch, 5.1 * inch, 1.5 * inch)
    # c.line(5.9 * inch, 6.6 * inch, 5.9 * inch, 0.6 * inch)

    c.line(6.8 * inch, 9.7 * inch, 6.8 * inch, -0.7 * inch)

    # Client
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 8.4 * inch, 'Client')
    c.drawString(0.7 * inch, 8.4 * inch, po_details['Company_name'])

    # Client Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 8.2 * inch, po_details['Supplier_address1'])
    c.drawString(0.7 * inch, 8.0 * inch, po_details['Supplier_address2'])
    c.drawString(0.7 * inch, 7.8 * inch, po_details['Supplier_address3'])

    # Attn
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 7.6 * inch, 'Attn')
    c.drawString(0.7 * inch, 7.6 * inch, po_details['Attn'])

    # PO Details
    c.setFont("Helvetica-Bold", 10)
    c.drawString(4.8 * inch, 8.4 * inch, 'PO No')
    c.drawString(4.8 * inch, 8.2 * inch, 'PO Date')
    c.drawString(4.8 * inch, 8.0 * inch, 'Terms')
    c.drawString(4.8 * inch, 7.8 * inch, 'Currency')
    c.drawString(4.8 * inch, 7.6 * inch, 'Ref')

    po_date_str = po_details['PO_Date']
    print("...............po_date_str....................",po_date_str)
    from dateutil import parser

    try:
        po_date = parser.parse(po_date_str)
        print("...............po_date....................",po_date)
        formatted_po_date = po_date.strftime('%d-%m-%Y')
    except ValueError:
        formatted_po_date = po_date_str  # Fallback to original if parsing fails
        print("...............formatted_po_date....................",formatted_po_date)
    # PO Values
    c.setFont("Helvetica", 10)
    c.drawString(5.6 * inch, 8.4 * inch, po_details['PO_no'])
    c.drawString(5.6 * inch, 8.2 * inch, formatted_po_date)
    c.drawString(5.6 * inch, 8.0 * inch, po_details['Payment_Terms'])
    c.drawString(5.6 * inch, 7.8 * inch, po_details['Currency'])
    c.drawString(5.6 * inch, 7.6 * inch, po_details['Quote_Ref'])

    # Delivery Details
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.02 * inch, 7.3 * inch, 'Delivery')
    c.drawString(0.7  * inch, 7.3 * inch, po_details['Delivery'])

    # Delivery Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 7.1 * inch, po_details['Address_Line1'])
    c.drawString(0.7 * inch, 6.9 * inch, po_details['Address_Line2'])
    c.drawString(0.7 * inch, 6.7 * inch, '')

    # Delivery Contact Details
    c.setFont("Helvetica-Bold", 10)
    c.drawString(4.8 * inch, 7.3 * inch, 'Lead Time')
    c.drawString(4.8 * inch, 7.1 * inch, 'Contact')
    c.drawString(4.8 * inch, 6.9 * inch, 'Phone No')
    c.drawString(4.8 * inch, 6.7 * inch, 'Page')

    # Delivery Values
    c.setFont("Helvetica", 10)
    c.drawString(5.6 * inch, 7.3 * inch, po_details['leat_time'])
    c.drawString(5.6 * inch, 7.1 * inch, po_details['created_by'])
    c.drawString(5.6 * inch, 6.9 * inch, str(po_details['phone_number']))
    c.drawString(5.6 * inch, 6.7 * inch, '1 of 1')

    # Item table heading
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 6.4 * inch, 'Item')
    c.drawString(0.8 * inch, 6.4 * inch, 'Part No')
    c.drawString(2.5 * inch, 6.4 * inch, 'description')
    c.drawString(4.2 * inch, 6.4 * inch, 'UOM')
    c.drawString(4.73 * inch, 6.4 * inch, 'Qty')
    c.drawString(5.2 * inch, 6.4 * inch, 'Unit Price')
    c.drawString(6.0 * inch, 6.4 * inch, 'Total Price')

    #Signature
    # c.drawString(0.8 * inch, -0.4 * inch, 'Acknowledged & Accepted By')
    # c.drawString(4.2 * inch, -0.4 * inch, 'for Centroid Engineering Solutions')
    # c.drawString(2.0 * inch, -0.65 * inch, 'This is a system generated PO no signature is required.')

    # c.line(0, 1.5 * inch, 6.8 * inch, 1.5 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)
    # c.line(0, -0.2 * inch, 6.8 * inch, -0.2 * inch)  # above acknowledge

# Define the function
def po_pdf(c, data_dict, total_sum, po_details):
    print(".........data_dict.......",data_dict)
    po_pdf_hedder(c, po_details)

    # Draw items in a table
    import textwrap
    row_height = 0.3 * inch
    start_y = 6.0 * inch
    current_y = start_y  # Initialize current_y here

    gst_status = None

    for index, item_row in enumerate(data_dict):
        print(".....item_row..........",item_row)
        print("........index,hight.............",index,current_y)

        if current_y <= - 5:  # Add new page after every 30 items
            print("......current_y.....",current_y)
            c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, -0.7 * inch)
            c.line(1.5 * inch, 6.6 * inch, 1.5 * inch, -0.7 * inch)
            c.line(4.1 * inch, 6.6 * inch, 4.1 * inch, -0.7 * inch)
            c.line(4.6 * inch, 6.6 * inch, 4.6 * inch, -0.7 * inch)
            c.line(5.1 * inch, 6.6 * inch, 5.1 * inch, -0.7 * inch)
            c.line(5.9 * inch, 6.6 * inch, 5.9 * inch, -0.7 * inch)
            c.showPage()
            po_pdf_hedder(c, po_details)
            row_height = 0.3 * inch
            start_y = 6.0 * inch
            current_y = start_y

        part_no = item_row['Part_No']
        item = item_row['item']
        quantity = item_row['quantity']
        unit_price = item_row['Unit_Price']
        total_price = item_row['total']
        uom = item_row['uom']
        gst_status = item_row['GST']

        c.setFont("Helvetica", 10)
        c.drawString(0.2 * inch, current_y, str(index + 1))
        # c.drawString(0.6 * inch, current_y,  part_no)

        pn = 1

        if len(part_no) > 10:
            part = current_y
            pn = 2
            lines = textwrap.wrap(part_no, width=10)
            for i, line in enumerate(lines):
                if i == 0:
                    c.drawString(0.6 * inch, current_y, line)
                else:
                    current_y -= 0.25 * inch
                    c.drawString(0.6 * inch, current_y, line)
        else:
            c.drawString(0.6 * inch, current_y, part_no)

        if pn == 2:
            current_y = part
        else:
            pass

        ite = 1

        if len(item) > 37:
            itemheight = current_y
            ite = 2
            lines = textwrap.wrap(item, width=37)
            for i, line in enumerate(lines):
                if i == 0:
                    c.drawString(1.6 * inch, current_y, line)
                else:
                    current_y -= 0.25 * inch
                    c.drawString(1.6 * inch, current_y, line)
        else:
            c.drawString(1.6 * inch, current_y, item)

        if ite == 2:
            current_y = itemheight
        else:
            pass

        c.drawString(4.2 * inch, current_y, f"{uom}")
        c.drawString(4.78 * inch, current_y, f"{quantity}")
        c.drawString(5.2 * inch, current_y, f"{unit_price:.2f}")
        c.drawString(6.0 * inch, current_y, str(total_price))

        # Update current_y for the next item
        if pn != 1 or ite != 1:
            print("..........pn........",pn)
            print("..........ite........",ite)
            print(".......current_y -= row_height + 0.25 * inch...............")
            current_y -= row_height + 0.25 * inch
        else:
            current_y -= row_height
            print("..........pn........",pn)
            print("..........ite........",ite)
            print("...............current_y -= row_height.....................")

    if current_y <= 93.60:  # Add new page after every 30 items
        print('####################################################..........',current_y, 1.3 * inch)

        c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, -0.7 * inch)
        c.line(1.5 * inch, 6.6 * inch, 1.5 * inch, -0.7 * inch)
        c.line(4.1 * inch, 6.6 * inch, 4.1 * inch, -0.7 * inch)
        c.line(4.6 * inch, 6.6 * inch, 4.6 * inch, -0.7 * inch)
        c.line(5.1 * inch, 6.6 * inch, 5.1 * inch, -0.7 * inch)
        c.line(5.9 * inch, 6.6 * inch, 5.9 * inch, -0.7 * inch)
        c.showPage()
        po_pdf_hedder(c, po_details)

        c.line(0, 6.3 * inch, 6.8 * inch, 1.5* inch)
        # Diagonal from bottom left to top right
        c.line(0, 1.5* inch, 6.8 * inch, 6.3 * inch)

    elif current_y >= 93.60:
        c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, 1.5 * inch) # 6 horizontal lines
        c.line(1.5 * inch, 6.6 * inch, 1.5 * inch, 1.5 * inch)
        c.line(4.1 * inch, 6.6 * inch, 4.1 * inch, 1.5 * inch)
        c.line(4.6 * inch, 6.6 * inch, 4.6 * inch, 0.6 * inch)
        c.line(5.1 * inch, 6.6 * inch, 5.1 * inch, 1.5 * inch)
        c.line(5.9 * inch, 6.6 * inch, 5.9 * inch, 0.6 * inch)

    c.setFont("Helvetica-Bold", 10)
    c.line(4.6 * inch, 1.2 * inch, 6.8 * inch, 1.2 * inch) #three small lines
    c.line(4.6 * inch, 0.9 * inch, 6.8 * inch, 0.9 * inch)
    c.line(4.6 * inch, 0.6 * inch, 6.8 * inch, 0.6 * inch)

    c.line(4.6 * inch, 1.5 * inch, 4.6 * inch, 0.6 * inch) #two samll lines
    c.line(5.9 * inch, 1.5 * inch, 5.9 * inch, 0.6 * inch) #two samll lines

    c.drawString(4.8 * inch, 1.3 * inch, f"Total ({po_details['Currency']})")
    c.drawString(4.9 * inch, 1.0 * inch, 'GST (9%)')
    c.drawString(4.8 * inch, 0.7 * inch, f"Total ({po_details['Currency']})")

    #comments
    c.drawString(0.1 * inch, 1.3 * inch, 'Comments')
    # c.setFont("Helvetica", 10)
    c.drawString(0.8 * inch, 1.0 * inch, po_details['comments'])


    c.setFont("Helvetica-Bold", 10)
    print("...............gst_status.......................%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%...............",gst_status)
    # Ensure total_sum is treated as a float
    total_sum = float(total_sum.replace(',', ''))


    # Check GST status and calculate GST if applicable
    if gst_status != 0.0:
        gst = 0.09 * total_sum
        gst1 = total_sum * 0.09
    else:
        gst = 0
        gst1 = 0

    # Calculate the total with GST
    total_with_gst = round(total_sum + gst1, 2)

    # Format the values for display
    total_sum_formatted = "{:,.2f}".format(total_sum)
    total_with_gst_formatted = "{:,.2f}".format(total_with_gst)


    c.drawString(5.92 * inch, 1.3 * inch, f"$")
    c.drawString(5.92 * inch, 1.0 * inch, f"$")
    c.drawString(5.92 * inch, 0.7 * inch, f"$")

    c.drawString(6.02 * inch, 1.3 * inch, str(total_sum_formatted))
    c.drawString(6.02 * inch, 1.0 * inch, f"{gst:.2f}")
    c.drawString(6.02 * inch, 0.7 * inch, str(total_with_gst_formatted))

    #Signature
    c.drawString(0.8 * inch, -0.4 * inch, 'Acknowledged & Accepted By')
    c.drawString(4.2 * inch, -0.4 * inch, 'for Centroid Engineering Solutions')
    c.drawString(2.0 * inch, -0.65 * inch, 'This is a system generated PO no signature is required.')

    c.line(0, 1.5 * inch, 6.8 * inch, 1.5 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)
    c.line(0, -0.2 * inch, 6.8 * inch, -0.2 * inch)

    return c

def po_pdf_and_refresh(pdf_filename):
    # Implementing a response to serve the PDF and refresh the page
    return f'''
        <script>
            const anchor = document.createElement('a');
            anchor.href = '/download_po/{pdf_filename}';
            anchor.download = '{pdf_filename}';
            anchor.click();
            window.location.href = '/admin_pr';
        </script>
    '''

@app.route('/download_po/<filename>')
def download_po(filename):
    temp_dir = '/tmp'  # Temporary directory on the server
    pdf_path = os.path.join(temp_dir, filename)
    try:
        return send_file(pdf_path, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Error downloading PDF: {e}")
        flash(f'Error downloading PDF: {str(e)}', 'error')
        return redirect(url_for('admin_pr'))




##--------------------------------------------------------PROJECTS------------------------------------------------------------------------------------------------------------------

from datetime import datetime
@app.route('/projects')
@login_required
def projects():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    import datetime  # Ensure you import the datetime module

    user = get_current_user()
    user_name = user['name']
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()

    department_code = get_department_code_by_username( user['name'])
    # print(".........................",department_code)
    # Define the custom order for statuses
    custom_status_order = ['Open', 'Design', 'Install', 'Testing', 'Closed']

    # Query to get the status counts
    status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
    totalstatus = db.execute(status_query)
    status_counts = dict(totalstatus.fetchall())



    # Query to get the total count of all projects
    total_projects_query = 'SELECT COUNT(*) FROM projects'
    total_projects_result = db.execute(total_projects_query).fetchone()
    if total_projects_result:
        total_projects = total_projects_result[0]
    else:
        total_projects = 0
    # print("...............total_projects.......", total_projects)
    ordered_status_values = [0, 0, 0, 0, 0]  # Initialize with zeros
    total_eq_query = 'SELECT COUNT(*) FROM enquiries'
    total_eqs = db.execute(total_eq_query).fetchone()[0]

    # Check if there are any projects before generating the plot
    if total_projects > 0:
        ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]
        # print(ordered_status_values)

        status_counts = {
            'Open': ordered_status_values[0],
            'Build': ordered_status_values[1],
            'Install': ordered_status_values[2],
            'Testing': ordered_status_values[3],
            'Closed': ordered_status_values[4],
            'Total Projects': total_projects
        }
        import matplotlib.pyplot as plt
        import io
        import base64

        colors = plt.cm.Set3.colors
        brighter_colors = ['red', 'green', 'blue', 'skyblue', 'orange', 'SlateBlue']
        # ...
        explode = (0.05, 0.05, 0.05, 0.05, 0.05)

        fig, ax = plt.subplots(figsize=(3, 3))
        wedges, texts, autotexts = ax.pie(
            ordered_status_values,
            colors=brighter_colors,
            startangle=90,
            wedgeprops=dict(width=0.15, linewidth=0.5, edgecolor='white'),
            autopct=lambda p: '{:.0f}'.format(p * total_projects / 100),
            pctdistance=1.1,
            explode=explode
        )

        ax.axis('equal')  # Equal aspect ratio ensures that the pie is drawn as a circle.
        total_text = ax.text(0, 0, f'\n{total_projects}\nProjects', ha='center', va='center', fontsize=10,
                            fontweight='bold', color='#004B5D')

        # Create legend labels with counts
        legend_labels = [f'{status}: {count}' for status, count in status_counts.items()]

        # Add legend with circle markers and value counts
        legend_handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10) for color
                        in brighter_colors]
        legend = ax.legend(legend_handles, legend_labels, title="Status", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))

        # Remove the box around the legend
        legend.get_frame().set_linewidth(0)  # This line removes the border around the legend

        # Save the donut plot image
        donut_plot_stream = io.BytesIO()
        plt.savefig(donut_plot_stream, format='png', bbox_inches='tight')
        donut_plot_stream.seek(0)
        donut_plot_data = base64.b64encode(donut_plot_stream.getvalue()).decode()

        # Close the plot to free up resources
        plt.close()
    else:
        # Handle the case when there are no projects
        donut_plot_data = None




    # Query to get the total number of users
    total_users_query = 'SELECT COUNT(*) FROM admin_user'
    total_users = db.execute(total_users_query).fetchone()[0]

    #leave
    leaves_on_current_day_query = """SELECT COUNT(DISTINCT employeeID) AS number_of_employees FROM leaves WHERE STRFTIME('%Y-%m-%d', leave_date) = DATE('now')"""
    leaves_on_current_day = db.execute(leaves_on_current_day_query).fetchone()[0]
    from datetime import datetime
    # Get the current month and year
    current_month_year = datetime.now().strftime('%Y-%m')

    # SQL query to get the count of days used till today for each employee in the current month
    leaves_on_current_month_query = """ SELECT employeeID, COUNT(*) AS total_days_on_leave, SUM(CASE WHEN leave_date <= DATE('now') THEN 1 ELSE 0 END) AS days_used_till_today
        FROM leaves WHERE strftime('%Y-%m', leave_date) = ? GROUP BY employeeID """

    # Execute the SQL query
    leaves_on_current_month_result = db.execute(leaves_on_current_month_query, (current_month_year,)).fetchall()

    # Process the results and generate HTML rows

    leave_rows = []
    for row in leaves_on_current_month_result:
        employee_name = row['employeeID']
        total_days_on_leave = row['total_days_on_leave']
        days_used_till_today = row['days_used_till_today']

        # Set colors
        color_days_used = 'red'
        color_total_days = 'green'
        color_slash = 'black'

        # Append the HTML row to the list with inline styles
        leave_rows.append(f"<tr><td>{employee_name}</td>"
                        f"<td style='color: {color_days_used}'>{days_used_till_today}"
                        f"<span style='color: {color_slash};'>/</span>"
                        f"<span style='color: {color_total_days}'>{total_days_on_leave}</span> </td></tr>")

    # Combine the HTML rows into a string
    leave_table_html = ''.join(leave_rows)

    cursor.execute("SELECT COUNT(*) FROM claims WHERE claim_by = ?", (user_name,))
    user_total_claims = cursor.fetchone()[0]

    # Query to get the number of claims where the status is not approved
    cursor.execute("SELECT COUNT(*) FROM claims  WHERE status != 'Approved' AND  claim_by = ?", (user_name,))
    user_unapproved_claims = cursor.fetchone()[0]


    return render_template('admin_templates/projects/projects_main_page.html',is_pm=is_pm,user=user,department_code=department_code,donut_plot_data=donut_plot_data,
                           total_users=total_users,leave_table_html=leave_table_html,total_eqs=total_eqs, user_total_claims=user_total_claims, user_unapproved_claims= user_unapproved_claims,
                            ordered_status_values=ordered_status_values,total_projects=total_projects,leaves_on_current_day=leaves_on_current_day)

import locale
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
@app.route('/admin_project_edit/<int:proid>', methods=['GET', 'POST'])
@login_required
def admin_project_edit(proid):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

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
        pmtable_cur = db.execute('SELECT * FROM pmtable WHERE project_id = ?', [project_details['id']])
        from_pmtable_rows = pmtable_cur.fetchall()
        working_hours_cur = db.execute("SELECT departmentID, SUM(hoursWorked) AS hours_worked FROM workingHours WHERE projectID = ? GROUP BY departmentID",[project_details['id']])
        from_working_hours = working_hours_cur.fetchall()
        cost_cur = db.execute("SELECT department_code, total AS hours_worked FROM manual_entry WHERE project_id = ? GROUP BY department_code",[project_details['id']])
        cost_hours = cost_cur.fetchall()

        # Create dictionaries to store department-wise information
        department_data = {}
        department_data1 = {}
        department_data10 = {}

        # Process data from pmtable
        for pmtable_row in from_pmtable_rows:
            project_id, username, department_code, hours, added_hours, total = pmtable_row
            department_code = int(department_code)
            if department_code not in department_data:
                department_data[department_code] = [0.0, 0.0, 0.0]  # Initialize values
            # Update values for the department
            department_data[department_code][0] += hours
            department_data[department_code][1] += added_hours
            department_data[department_code][2] += total

        # Process data from workingHours
        for working_hours_row in from_working_hours:
            department_id, hours_worked = working_hours_row
            if department_id not in department_data1:
                department_data1[department_id] = [0.0]  # Initialize values
            # Update values for the department
            department_data1[department_id][0] += hours_worked

        # Process data from cost_hours
        for working_hours_row in cost_hours:
            department_id, hours_worked = working_hours_row
            department_id = int(department_id)  # Convert department_id to int
            if department_id not in department_data10:
                department_data10[department_id] = [0.0]  # Initialize values
            # Update values for the department
            department_data10[department_id][0] += hours_worked

        print("............department_data10...............\n",department_data10)

        # Now 'department_data' contains information grouped by department ID
        department_data2 = {}

        # Merge data from department_data
        for key, values in department_data.items():
            department_data2[key] = values + [0.0]  # Add a placeholder for hours_worked

        # Merge data from department_data1
        for key, values in department_data1.items():
            if key in department_data2:
                department_data2[key][-1] = values[0]  # Update the placeholder with the actual value
            else:
                department_data2[key] = [0.0, 0.0, 0.0, values[0]]

        # Merge data from department_data10
        for key, values in department_data10.items():
            if key in department_data2:
                department_data2[key][-1] = values[0]  # Update the placeholder with the actual value
            else:
                department_data2[key] = [0.0, 0.0, 0.0, values[0]]

        print("............department_data2...............\n",department_data2)

        return render_template('admin_templates/projects/admin_project_edit.html', user=user, single_pro = single_pro,project_details=project_details,department_code=department_code1, is_pm = is_pm,usernames=usernames, pmtable_rows=department_data2)
    else:
        return render_template('admin_templates/projects/admin_project_edit.html', user=user, single_pro = single_pro,project_details=project_details,department_code=department_code, is_pm = is_pm,usernames=usernames, pmtable_rows=department_data2)

def calculate_working_hours(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016]

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

    cursor.close()

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
    all_department_codes = [2001, 2002, 2003, 2004, 2005, 3001, 3002, 3003, 3004, 3005, 3006, 4001, 4002, 4003, 4004, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514 ]

    # Query to get allocated hours from pmtable for specific department codes
    pm_query = "SELECT department_code, total FROM pmtable WHERE project_id = ?"
    cursor.execute(pm_query, (project_id,))
    pm_data = cursor.fetchall()

    # Query to get worked hours from manual_entry table
    cost_query = "SELECT department_code, total AS hours_worked FROM manual_entry WHERE project_id = ? GROUP BY department_code"
    cursor.execute(cost_query, (project_id,))
    cost_data = cursor.fetchall()

    cursor.close()

    pm_df = pd.DataFrame(pm_data, columns=['department_code', 'allocated_hours'])
    cost_df = pd.DataFrame(cost_data, columns=['department_code', 'hours_worked'])

    # Ensure both 'department_code' columns have the same data type (int32)
    pm_df['department_code'] = pm_df['department_code'].astype('int32')
    cost_df['department_code'] = cost_df['department_code'].astype('int32')

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
    department_codes = [2001,2002,2003,2004,2005,2006]

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

def calculate_sub_contract_cost(project_id):
    db = get_database()
    cursor = db.cursor()

    # List of department codes to include in the query
    department_codes = [3001,3002,3003,3004,3005,3006]

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

import plotly.graph_objects as go
import plotly.io as pio

@app.route('/graph/<int:project_id>')
@login_required
def generate_graph(project_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    username = user['name']
    department_code = get_department_code_by_username(username)
    merged_df = calculate_working_hours(project_id)
    cost_df = calculate_project_cost(project_id)
    # print("...........cost_df1..............\n",cost_df)
    ranges = [(2001, 2006), (3001, 3010), (4001, 4004), (501, 513)]
    cost_df['department_code'] = pd.to_numeric(cost_df['department_code'], errors='coerce', downcast='integer')
    # Create separate DataFrames
    # print("...........cost_df2..............\n",cost_df)


    dfs = {}
    for range_ in ranges:
        start, end = range_
        key = f'df_{start}_{end}'
        dfs[key] = cost_df[cost_df['department_code'].between(start, end)]

    df_2001_2006 = dfs['df_2001_2006']
    df_3001_3010 = dfs['df_3001_3010']
    df_4001_4004 = dfs['df_4001_4004']
    df_501_513 = dfs['df_501_513']
    # print("...........df_501_513######################..............\n",cost_df)


    # Calculate the sum of allocated_hours and hours_worked
    sum_allocated_hours_1000 = merged_df['allocated_hours'].sum()
    sum_hours_worked_1000 = merged_df['hours_worked'].sum()

    # Calculate the sum of allocated_hours and hours_worked for df_2001_2006
    sum_allocated_hours_2000 = df_2001_2006['allocated_hours'].sum()
    sum_hours_worked_2000 = df_2001_2006['hours_worked'].sum()

    # Calculate the sum of allocated_hours and hours_worked
    sum_allocated_hours_3000 = df_3001_3010['allocated_hours'].sum()
    sum_hours_worked_3000 = df_3001_3010['hours_worked'].sum()

    # Calculate the sum of allocated_hours and hours_worked for df_4001_4004
    sum_allocated_hours_4000 = df_4001_4004['allocated_hours'].sum()
    sum_hours_worked_4000 = df_4001_4004['hours_worked'].sum()

    # Calculate the sum of allocated_hours and hours_worked for df_4001_4004
    sum_allocated_hours_501 = df_501_513['allocated_hours'].sum()
    sum_hours_worked_501 = df_501_513['hours_worked'].sum()

    # Create a new row for department_code 3000 with the calculated sums
    new_row_1000 = {'department_code': 1000,'Description':'Resource', 'allocated_hours': sum_allocated_hours_1000, 'hours_worked': sum_hours_worked_1000}
    new_row_3000 = {'department_code': 3000,'Description':'Sub Contract','allocated_hours': sum_allocated_hours_3000, 'hours_worked': sum_hours_worked_3000}
    new_row_2000 = {'department_code': 2000,'Description':'Material','allocated_hours': sum_allocated_hours_2000, 'hours_worked': sum_hours_worked_2000}
    new_row_4000 = {'department_code': 4000,'Description':'Optional','allocated_hours': sum_allocated_hours_4000, 'hours_worked': sum_hours_worked_4000}
    new_row_501 = {'department_code': 500,'Description':'Others','allocated_hours': sum_allocated_hours_501, 'hours_worked': sum_hours_worked_501}

    summary_table = pd.DataFrame(columns=['department_code','Description', 'allocated_hours', 'hours_worked'])
    # Append the new row to the original data frame
    # summary_table = summary_table.append([new_row_1000,new_row_3000, new_row_2000, new_row_4000], ignore_index=True)
    summary_table = pd.DataFrame([new_row_1000,new_row_2000,new_row_3000, new_row_4000, new_row_501], columns=['department_code', 'Description','allocated_hours', 'hours_worked'])
    summary_table['department_code'] = summary_table['department_code'].astype(int)
    print('summary_table.......\n',summary_table)
    print("..........merged_df...........\n",merged_df)


    # Print the resulting data frame
    sumA = summary_table['allocated_hours'].sum()
    sumH = summary_table['hours_worked'].sum()
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT po_value FROM projects WHERE id = ?', [project_id,])
    po_value_row = cursor.fetchone()
    if po_value_row and po_value_row[0]:
        po_value_str = str(po_value_row[0]).replace(',', '')
        po_value = float(po_value_str)
        # print(".......po_value..........", po_value)
    else:
        # Handle the case where 'po_value' is None or not a string
        po_value = 0  # or any default value you prefer

    if po_value  > 0:
        margin = (po_value - sumH) / po_value * 100
        ac_margin = round(margin, 2)
    else:
        ac_margin = 0

    if po_value  > 0:
        budget = (po_value - sumA) / po_value * 100
        budget_margin = round(budget, 2)
    else:
        budget_margin = 0

    # Create traces for allocated hours and hours worked
    trace_allocated = go.Bar(y=summary_table['department_code'],x= summary_table['allocated_hours'],orientation='h',text=summary_table['allocated_hours'],name='Allocated',marker=dict(color='rgb(55, 83, 109 )'))
    trace_actual = go.Bar(y=summary_table['department_code'],x=summary_table['hours_worked'],orientation='h',text=summary_table['hours_worked'],name='Actual',marker=dict(color='rgb(26, 118, 255)'))
    # Create the figure
    fig = go.Figure(data=[trace_allocated, trace_actual])
    # Update layout
    fig.update_layout(
        title=dict( text='<b>Summary</b>',x=0.5, y=0.98,xanchor='center', yanchor='top', font=dict(family='Arial', size=16, color='Blue'), pad=dict(b=10)),
        yaxis=dict(title='Code'),
        xaxis=dict(title='Cost(SGD)'), barmode='group', bargap=0.15,bargroupgap=0.1, margin=dict(l=20, r=20, t=40, b=20),legend=dict(x=0.9, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)'))

    # Convert the plot to base64
    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    summary_gra = base64.b64encode(img_buf).decode('utf-8')


    # resouces graph
    # Assuming merged_df is correctly populated and has appropriate columns
    fig = go.Figure()
    # Add trace for Allocated hours
    fig.add_trace(go.Bar(x=merged_df['department_code'], y=merged_df['allocated_hours'],text=merged_df['allocated_hours'],  name='Allocated', marker_color='rgb(0.4940, 0.1840, 0.5560)'  ))
    # Add trace for Actual hours worked
    fig.add_trace(go.Bar( x=merged_df['department_code'],y=merged_df['hours_worked'], text=merged_df['hours_worked'],name='Actual', marker_color='rgb(0.8500, 0.3250, 0.0980)'))

    # Update layout with title, axis labels, and formatting
    fig.update_layout(
        title=dict(text='<b>Resource</b>', x=0.5, y=0.98, xanchor='center', yanchor='top', font=dict(family='Arial', size=16, color='Blue'), pad=dict(b=10)),
        xaxis=dict(title='Code', tickmode='array', tickvals=merged_df['department_code'], ticktext=merged_df['department_code']),
        yaxis=dict(title='Hours'),
        barmode='group',  # Group bars for each department_code
        bargap=0.15,  # Gap between bars
        bargroupgap=0.1,  # Gap between groups of bars
        margin=dict(l=20, r=20, t=40, b=20),  # Margin around the plot
        legend=dict(x=0, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)')  # Position and style of legend
    )
    # Convert the plot to base64 for embedding or display
    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    img_base64 = base64.b64encode(img_buf).decode('utf-8')




    fig = go.Figure()
    fig.add_trace(go.Bar( x=df_2001_2006['department_code'], y=df_2001_2006['allocated_hours'], text=df_2001_2006['allocated_hours'], name='Budget',  marker_color='rgba(246, 78, 139, 0.6)' ))
    fig.add_trace(go.Bar( x=df_2001_2006['department_code'], y=df_2001_2006['hours_worked'], text=df_2001_2006['hours_worked'], name='Actual',marker_color='rgba(58, 71, 80, 0.6)' ))
    fig.update_layout(
        title=dict( text='<b>Material</b>', x=0.5, y=0.98, xanchor='center',yanchor='top',font=dict( family='Arial',  size=16,  color='blue' ),pad=dict(b=10)),
        xaxis=dict(title='Code', tickmode='array', tickvals=df_2001_2006['department_code'], ticktext=df_2001_2006['department_code']),
        yaxis=dict(title='Cost (SGD)'),barmode='group', bargap=0.15, bargroupgap=0.1,margin=dict(l=20, r=20, t=40, b=20),legend=dict(x=0, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)'))

    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    Material_gra = base64.b64encode(img_buf).decode('utf-8')


    fig = go.Figure()
    fig.add_trace(go.Bar( x=df_3001_3010['department_code'], y=df_3001_3010['allocated_hours'],text=df_3001_3010['allocated_hours'],name='Budget',marker_color='rgb(166, 66, 11)'))
    fig.add_trace(go.Bar( x=df_3001_3010['department_code'], y=df_3001_3010['hours_worked'], text=df_3001_3010['hours_worked'], name='Actual', marker_color='rgb(128,128,0)'))
    fig.update_layout(
        title=dict( text='<b>Sub Contract</b>', x=0.5, y=0.98, xanchor='center',yanchor='top',font=dict( family='Arial',  size=16,  color='blue' ),pad=dict(b=10)),
        xaxis=dict(title='Code', tickmode='array', tickvals=df_3001_3010['department_code'], ticktext=df_3001_3010['department_code']),
        yaxis=dict(title='Cost (SGD)'),barmode='group', bargap=0.15, bargroupgap=0.1,margin=dict(l=20, r=20, t=40, b=20), legend=dict(x=0, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)'))

    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    Sub_Contract_gra = base64.b64encode(img_buf).decode('utf-8')
    fig = go.Figure()


    fig.add_trace(go.Bar(x=df_4001_4004['department_code'], y=df_4001_4004['allocated_hours'],text=df_4001_4004['allocated_hours'],name='Budget', marker_color='rgb(220,20,60)'))
    fig.add_trace(go.Bar(x=df_4001_4004['department_code'], y=df_4001_4004['hours_worked'],text=df_4001_4004['hours_worked'],name='Actual', marker_color='rgb(222,184,135)'))
    fig.update_layout(
        title=dict( text='<b>Others</b>', x=0.5, y=0.98, xanchor='center',yanchor='top',font=dict( family='Arial',  size=16,  color='blue' ),pad=dict(b=10)),
        xaxis=dict(title='Code', tickmode='array', tickvals=df_4001_4004['department_code'], ticktext=df_4001_4004['department_code']),
        yaxis=dict(title='Cost (SGD)'), barmode='group', bargap=0.15, bargroupgap=0.1, margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(x=0, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)'))

    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    optional_gra = base64.b64encode(img_buf).decode('utf-8')

    print("........df_501_513..................\n",df_501_513)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df_501_513['department_code'], y=df_501_513['allocated_hours'], text=df_501_513['allocated_hours'], name='Budget', marker_color='rgb(220,20,60)'))
    fig.add_trace(go.Bar(x=df_501_513['department_code'], y=df_501_513['hours_worked'], text=df_501_513['hours_worked'], name='Actual', marker_color='rgb(222,184,135)'))
    fig.update_layout(
        title=dict(text='<b>Others</b>', x=0.5, y=0.98, xanchor='center', yanchor='top', font=dict(family='Arial', size=16, color='blue'), pad=dict(b=10)),
        xaxis=dict(title='Code', tickmode='array', tickvals=df_501_513['department_code'], ticktext=df_501_513['department_code']),
        yaxis=dict(title='Cost (SGD)'), barmode='group', bargap=0.15, bargroupgap=0.1, margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(x=0, y=1.0, bgcolor='rgba(255, 255, 255, 0)', bordercolor='rgba(255, 255, 255, 0)'))

    img_buf = pio.to_image(fig, format='png', width=1020, height=645)
    others_gra = base64.b64encode(img_buf).decode('utf-8')


    db = get_database()
    user = get_current_user()
    pro_cur = db.execute('select * from projects where id = ?', [project_id])
    project_details = get_project_details(project_id)

    return render_template('admin_templates/projects/admin_graph_view.html',user=user,others_gra=others_gra,Sub_Contract_gra=Sub_Contract_gra,Material_gra=Material_gra,summary_table=summary_table,
                           ac_margin=ac_margin, budget_margin=budget_margin,sumA=sumA,sumH=sumH,summary_gra=summary_gra, img_base64=img_base64,project_details=project_details,department_code=department_code,
                           optional_gra=optional_gra, is_pm = is_pm,project_id=project_id,po_value=po_value)

@app.route('/allocate_hours/<int:proid>', methods=['POST', 'GET'])
@login_required
def allocate_hours(proid):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    data = request.form.to_dict()
    print("allocate_hours.........................Data from main table:", data)

    user = get_current_user()
    cursor = db.cursor()

    for code, hours in data.items():

        if hours.strip():  # Check if it's not an empty or whitespace-only string
            hours_float = float(hours)
        else:
            # Handle the case where hours is empty or contains only whitespace
            hours_float = 0.0
        cursor.execute("SELECT 1 FROM pmtable WHERE department_code = ? AND project_id = ?", (code, proid))
        existing_record = cursor.fetchone()

        if existing_record:
            # Update the existing record
            cursor.execute("UPDATE pmtable SET added_hours = added_hours + ?, total = total + ? WHERE project_id = ? AND department_code = ?", (hours_float, hours_float, proid, code))
        else:
            # Insert a new record
            cursor.execute("INSERT INTO pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?)", (proid, code, hours_float, 0.0, hours_float))

        db.commit()
    return redirect(url_for('admin_project_edit', proid=proid))

from datetime import datetime, timedelta
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    user = get_current_user()
    active_tab = 'dashboard'
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute('SELECT DISTINCT strftime("%Y", start_time) as year FROM projects WHERE start_time IS NOT NULL ORDER BY year DESC')
    all_years = [row[0] for row in cursor.fetchall()]
    cursor.execute('SELECT id FROM projects ORDER BY id DESC ')
    project_id_suggestions = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT client FROM projects WHERE client IS NOT NULL')
    all_clients = sorted([row[0] for row in cursor.fetchall()])

    if request.method == 'POST':
        search_term = request.form.get('project_id')
        project = fetch_project_by_id(int(search_term))
        if project:
                # Define the custom order for statuses
            db = get_database()
            custom_status_order = ['Open', 'Design', 'Build','Installation', 'FAT', 'SAT', 'Closed']

            # Query to get the status counts
            status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
            totalstatus = db.execute(status_query)
            status_counts = dict(totalstatus.fetchall())

            # Query to get the total count of all projects
            total_projects_query = 'SELECT COUNT(*) FROM projects'
            total_projects = db.execute(total_projects_query).fetchone()[0]

            # Add the total count to the status_counts dictionary
            status_counts['Total Projects'] = total_projects

            # Create a list of values in the same order as custom_status_order
            ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]
            return render_template('admin_templates/projects/admin_dashboard_page.html',all_years=all_years,all_clients=all_clients, is_pm=is_pm,
                                   department_code=department_code, user=user, allpro=project,
                                   ordered_status_values=ordered_status_values,total_projects=total_projects)
        else:
            return render_template('project_not_found.html')

    elif request.method == 'GET':
        project_id = request.args.get('project_id') if request.args.get('project_id') else None
        selected_clients = request.args.getlist('selected_clients')
        selected_status = request.args.getlist('selected_checkboxes')
        selected_years = request.args.getlist('selected_years')
        selected_type = request.args.getlist('selected_type')
        # print("selected type,,,,,,,,,,,,,,,,,,,",selected_type)
        search_values = [project_id, 0,0]
        db = get_database()
        cursor = db.cursor()
        # Retrieve pm and pe for all projects
        cursor.execute('SELECT pm, pe FROM projects')
        results = cursor.fetchall()
        is_pm = False
        is_pe = False

        # Check if the user is PM or PE for any project
        for result in results:
            pm, pe = result
            if pm == user['name']:
                is_pm = True
            if pe == user['name']:
                is_pe = True
        user = user['name']
        # Construct the query based on the conditions
        query = 'SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE 1=1'
        params = []

        # Add PM/PE filter
        user = get_current_user()
        username = user['name']
        if department_code == 1000 or username == 'soodesh' or username == 'N.Mahendran':
            pass  # No additional filter
        elif is_pm:
            query += f" AND pm = '{username}'"
        elif is_pe:
            query += f" AND pe = '{username}'"
        else:
            query = 'SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE 1=2'

        if project_id is not None:
            query += f' AND id = "{project_id}"'
            selected_status = [ ]
            selected_clients = [ ]
            selected_years  = [ ]
            selected_type = []
        else:
            # Status condition
            status_condition = None

            if selected_status:
                status_condition = ' OR '.join([f"(status = '{status_value}')" for status_value in selected_status])

            # Year condition
            year_condition = None
            if selected_years:
                year_condition = ' OR '.join([f"(strftime('%Y', start_time) = '{year}')" for year in selected_years])

            # Type condition
            type_condition = None
            if selected_type:
                type_condition = ' OR '.join([f"(type = '{type}')" for type in selected_type])

            # Industry condition
            client_condition = None
            if selected_clients:
                client_condition = ' OR '.join([f"(client = '{client}')" for client in selected_clients])

            # Constructing the final query with proper grouping
            conditions = []
            if status_condition:
                conditions.append(f"({status_condition})")
            if year_condition:
                conditions.append(f"({year_condition})")
            if type_condition:
                conditions.append(f"({type_condition})")
            if client_condition:
                conditions.append(f"({client_condition})")

            if conditions:
                query += ' AND ' + ' AND '.join(conditions)

        # Order the data by end_time in descending order
        query += " ORDER BY id DESC"

        print(query)
        # Execute the query
        pro_cur = db.execute(query)

        # pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm,pe,po_number,status,po_value FROM projects WHERE id = ?',[search_term])
        allpro = []

        ordered_status_values = []
        print(allpro)

        for pro_row in pro_cur.fetchall():
            pro_dict = dict(pro_row)
            project_id = pro_dict['id']  # Assuming the primary key column name is 'id'

            if isinstance(pro_dict['po_value'], str):
                # If 'po_value' is a string, replace commas
                po_value_str = pro_dict['po_value'].replace(',', '')
                po_value = float(po_value_str) if po_value_str else 0.0
            else:
                # If 'po_value' is not a string, leave it as is
                po_value = float(pro_dict['po_value']) if pro_dict['po_value'] else 0.0

            # Now you can convert it to an integer if needed
            po_value = int(po_value)

            if po_value > 0:
                merged_df = calculate_working_hours(project_id)
                cost_df = calculate_project_cost(project_id)
                ranges = [(2001, 2006), (3001, 3010), (4001, 4004)]
                cost_df['department_code'] = cost_df['department_code'].astype('Int64')
                dfs = {}
                for range_ in ranges:
                    start, end = range_
                    key = f'df_{start}_{end}'
                    dfs[key] = cost_df[cost_df['department_code'].between(start, end)]

                df_2001_2006 = dfs['df_2001_2006']
                df_3001_3010 = dfs['df_3001_3010']
                df_4001_4004 = dfs['df_4001_4004']

                # Calculate the sum of allocated_hours and hours_worked
                sum_allocated_hours_1000 = merged_df['allocated_hours'].sum()
                sum_hours_worked_1000 = merged_df['hours_worked'].sum()

                # Calculate the sum of allocated_hours and hours_worked for df_2001_2006
                sum_allocated_hours_2000 = df_2001_2006['allocated_hours'].sum()
                sum_hours_worked_2000 = df_2001_2006['hours_worked'].sum()

                # Calculate the sum of allocated_hours and hours_worked
                sum_allocated_hours_3000 = df_3001_3010['allocated_hours'].sum()
                sum_hours_worked_3000 = df_3001_3010['hours_worked'].sum()

                # Calculate the sum of allocated_hours and hours_worked for df_4001_4004
                sum_allocated_hours_4000 = df_4001_4004['allocated_hours'].sum()
                sum_hours_worked_4000 = df_4001_4004['hours_worked'].sum()

                # Create a new row for department_code 3000 with the calculated sums
                new_row_1000 = {'department_code': 1000,'Description':'Resource', 'allocated_hours': sum_allocated_hours_1000, 'hours_worked': sum_hours_worked_1000}
                new_row_3000 = {'department_code': 3000,'Description':'Sub Contract','allocated_hours': sum_allocated_hours_3000, 'hours_worked': sum_hours_worked_3000}
                new_row_2000 = {'department_code': 2000,'Description':'Material','allocated_hours': sum_allocated_hours_2000, 'hours_worked': sum_hours_worked_2000}
                new_row_4000 = {'department_code': 4000,'Description':'Others','allocated_hours': sum_allocated_hours_4000, 'hours_worked': sum_hours_worked_4000}

                summary_table = pd.DataFrame(columns=['department_code','Description', 'allocated_hours', 'hours_worked'])
                # Append the new row to the original data frame
                # summary_table = summary_table.append([new_row_1000,new_row_3000, new_row_2000, new_row_4000], ignore_index=True)
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

            allpro.append(pro_dict)

            custom_status_order = ['Open', 'Design', 'Build','Installation', 'FAT', 'SAT', 'Closed']

            # Query to get the status counts
            status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
            totalstatus = db.execute(status_query)
            status_counts = dict(totalstatus.fetchall())

            # Query to get the total count of all projects
            total_projects_query = 'SELECT COUNT(*) FROM projects'
            total_projects = db.execute(total_projects_query).fetchone()[0]

            # Add the total count to the status_counts dictionary
            status_counts['Total Projects'] = total_projects

            # Create a list of values in the same order as custom_status_order
            ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]

        return render_template('admin_templates/projects/admin_dashboard_page.html',all_clients=all_clients,all_years=all_years,search_values=search_values, selected_type=selected_type,
                                selected_checkboxes=selected_status,selected_clients=selected_clients,selected_years=selected_years,project_id_suggestions=project_id_suggestions,
                               is_pm=is_pm,department_code=department_code,user=user, allpro=allpro,ordered_status_values=ordered_status_values)

@app.route('/admin_dashboard_page',methods=['GET', 'POST'])
@login_required
def admin_dashboard_page():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    # if user is not None and user['admin'] == 0:
    #     return redirect(url_for('home'))
    active_tab = 'dashboard'
    db = get_database()
    cursor = db.cursor()
    cursor.execute('SELECT client FROM projects')
    clilent_suggestions = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT id FROM projects ORDER BY id DESC ')
    project_id_suggestions = [row[0] for row in cursor.fetchall()]
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])

    cursor.execute('SELECT DISTINCT strftime("%Y", start_time) as year FROM projects WHERE start_time IS NOT NULL ORDER BY year DESC')
    all_years = [row[0] for row in cursor.fetchall()]


    cursor.execute('SELECT DISTINCT client FROM projects WHERE client IS NOT NULL')
    all_clients = sorted([row[0] for row in cursor.fetchall()])


    # Define the custom order for statuses
    custom_status_order = ['Open', 'Design', 'Build','Installation', 'FAT', 'SAT', 'Closed']

    # Query to get the status counts
    status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
    totalstatus = db.execute(status_query)
    status_counts = dict(totalstatus.fetchall())
    some_condition = True
    # Query to get the total count of all projects

    if department_code == 1000 or user['name'] == 'soodesh' or user['name'] == 'N.Mahendran':
        pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE status != "Closed" ORDER BY id DESC')

    elif is_he_pm_by_username(user['name']) or is_he_pe_by_username(user['name']):
        # Query for PMs and PEs
        if is_he_pm_by_username(user['name']):
            pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE (pm = ? OR pe = ?) AND status != "Closed" ORDER BY id DESC', (user['name'], user['name']))
        else:  # Query for PEs
            pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE pe = ? AND status != "Closed" ORDER BY id DESC', (user['name'],))

    elif some_condition:
        pro_cur = db.execute('SELECT id, client, project_name, start_time, end_time, pm, pe, po_number, status, po_value,type FROM projects WHERE pe = ? AND status != "Closed" ORDER BY id DESC', ('adtcdef',))


    total_projects_query = 'SELECT COUNT(*) FROM projects'
    total_projects = db.execute(total_projects_query).fetchone()[0]

    # Add the total count to the status_counts dictionary
    status_counts['Total Projects'] = total_projects

    # Create a list of values in the same order as custom_status_order
    ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]

    allpro = []

    for pro_row in pro_cur.fetchall():

        pro_dict = dict(pro_row)
        project_id = pro_dict['id']  # Assuming the primary key column name is 'id'
        # Check if 'po_value' is an integer
        if isinstance(pro_dict['po_value'], int):
            po_value = pro_dict['po_value']
        else:
            # Extract po_value and remove commas
            po_value_str = str(pro_dict['po_value']).replace(',', '')

            # Convert po_value to integer
            try:
                po_value = int(float(po_value_str))
            except ValueError:
                # Handle the case where conversion is not possible
                po_value = 0  # or set a default value

        if po_value > 0:
            merged_df = calculate_working_hours(project_id)
            # print("...............merged_df...................\n",merged_df)
            cost_df = calculate_project_cost(project_id)
            ranges = [(2001, 2006), (3001, 3010), (4001, 4004)]
            cost_df['department_code'] = pd.to_numeric(cost_df['department_code'], errors='coerce')
            cost_df['department_code'] = cost_df['department_code'].astype('Int64')
            # print("...............cost_df...................\n",cost_df)
            # Create separate DataFrames
            dfs = {}
            for range_ in ranges:
                start, end = range_
                key = f'df_{start}_{end}'
                dfs[key] = cost_df[cost_df['department_code'].between(start, end)]

            df_2001_2006 = dfs['df_2001_2006']
            df_3001_3010 = dfs['df_3001_3010']
            df_4001_4004 = dfs['df_4001_4004']

            # Calculate the sum of allocated_hours and hours_worked
            sum_allocated_hours_1000 = merged_df['allocated_hours'].sum()
            sum_hours_worked_1000 = merged_df['hours_worked'].sum()

            # Calculate the sum of allocated_hours and hours_worked for df_2001_2006
            sum_allocated_hours_2000 = df_2001_2006['allocated_hours'].sum()
            sum_hours_worked_2000 = df_2001_2006['hours_worked'].sum()

            # Calculate the sum of allocated_hours and hours_worked
            sum_allocated_hours_3000 = df_3001_3010['allocated_hours'].sum()
            sum_hours_worked_3000 = df_3001_3010['hours_worked'].sum()

            # Calculate the sum of allocated_hours and hours_worked for df_4001_4004
            sum_allocated_hours_4000 = df_4001_4004['allocated_hours'].sum()
            sum_hours_worked_4000 = df_4001_4004['hours_worked'].sum()

            # Create a new row for department_code 3000 with the calculated sums
            new_row_1000 = {'department_code': 1000,'Description':'Resource', 'allocated_hours': sum_allocated_hours_1000, 'hours_worked': sum_hours_worked_1000}
            new_row_3000 = {'department_code': 3000,'Description':'Sub Contract','allocated_hours': sum_allocated_hours_3000, 'hours_worked': sum_hours_worked_3000}
            new_row_2000 = {'department_code': 2000,'Description':'Material','allocated_hours': sum_allocated_hours_2000, 'hours_worked': sum_hours_worked_2000}
            new_row_4000 = {'department_code': 4000,'Description':'Others','allocated_hours': sum_allocated_hours_4000, 'hours_worked': sum_hours_worked_4000}

            summary_table = pd.DataFrame(columns=['department_code','Description', 'allocated_hours', 'hours_worked'])
            # Append the new row to the original data frame
            # summary_table = summary_table.append([new_row_1000,new_row_3000, new_row_2000, new_row_4000], ignore_index=True)
            summary_table = pd.DataFrame([new_row_1000,new_row_2000,new_row_3000, new_row_4000], columns=['department_code', 'Description','allocated_hours', 'hours_worked'])
            summary_table['department_code'] = summary_table['department_code'].astype(int)
            sumA = summary_table['allocated_hours'].sum()
            sumH = summary_table['hours_worked'].sum()
            margin = (po_value - sumH) / po_value * 100
            rounded_margin = round(margin, 2)
            pro_dict['margin'] = rounded_margin
            # print("......po_value > 0.......",pro_dict['margin'])
        else:
            pro_dict['margin'] = 0
            # print("......po_value <<<<<<<<<< 0.......",pro_dict['margin'])


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



        allpro.append(pro_dict)


    custom_status_order = ['Open', 'Design', 'Build','Installation', 'FAT', 'SAT', 'Closed']
    # eq_status = ['Pending','Won','Submitted','Lost']

    # Query to get the status counts
    status_query = 'SELECT status, COUNT(*) FROM projects GROUP BY status'
    totalstatus = db.execute(status_query)
    status_counts = dict(totalstatus.fetchall())
    # print("status_counts................",status_counts)

    # Query to get the total count of all projects
    total_projects_query = 'SELECT COUNT(*) FROM projects'
    total_projects = db.execute(total_projects_query).fetchone()[0]

    # Add the total count to the status_counts dictionary
    status_counts['Total Projects'] = total_projects

    # Create a list of values in the same order as custom_status_order
    ordered_status_values = [status_counts.get(status, 0) for status in custom_status_order]
    db.close()
    search_values = [0,0,'none']
    return render_template('admin_templates/projects/admin_dashboard_page.html',all_years=all_years,all_clients=all_clients,search_values=search_values,is_pm=is_pm,
                           department_code=department_code, user=user,clilent_suggestions=clilent_suggestions,project_id_suggestions=project_id_suggestions,
                           allpro=allpro, active_tab=active_tab,total_projects=total_projects,ordered_status_values=ordered_status_values)

@app.route('/manual_entry',methods=['GET', 'POST'])
@login_required
def manual_entry():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()

    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    # print("...............project_ids...........",project_ids)

    db.close()
    return render_template('admin_templates/projects/cost.html',is_pm=is_pm,department_code=department_code, user=user,project_ids=project_ids)

@app.route('/allocate_costs', methods=['POST', 'GET'])
@login_required
def allocate_costs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    data = request.form.to_dict()
    data = {k: v for k, v in data.items() if k not in ['project_id', 'selected_project_id']}

    print("Data from main table:", data)
    # if request.method == 'POST':

    user = get_current_user()
    cursor = db.cursor()
    project_id = request.form['project_id']


    for code, hours in data.items():

        if hours.strip():  # Check if it's not an empty or whitespace-only string
            hours_float = float(hours)
        else:
            # Handle the case where hours is empty or contains only whitespace
            hours_float = 0.0
        cursor.execute("SELECT 1 FROM manual_entry WHERE department_code = ? AND project_id = ?", (code, project_id))
        existing_record = cursor.fetchone()

        if existing_record:
            # Update the existing record
            cursor.execute("UPDATE manual_entry SET added_cost = added_cost + ?, total = total + ? WHERE project_id = ? AND department_code = ?", (hours_float, hours_float, project_id, code))
        else:
            # Insert a new record
            cursor.execute("INSERT INTO manual_entry (project_id, department_code, cost, added_cost, total) VALUES (?, ?, ?, ?, ?)", (project_id, code, hours_float, 0.0, hours_float))

        db.commit()
    return redirect(url_for('manual_entry'))

@app.route('/search_enquiry', methods=['GET', 'POST'])
@login_required
def search_enquiry():
    db = get_database()
    cursor = db.cursor()
    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_year = datetime.now().year
    cursor.execute('SELECT DISTINCT strftime("%Y", EnquiryReceived) as year FROM enquiries WHERE EnquiryReceived IS NOT NULL ORDER BY year DESC')
    all_years = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Client FROM enquiries WHERE Client IS NOT NULL')
    all_clients = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT DISTINCT SiteOrEndUser FROM enquiries WHERE SiteOrEndUser IS NOT NULL')
    all_sites = sorted([row[0] for row in cursor.fetchall()])

    if request.method == 'POST':
        enquiry_number = request.form.get('searchEQ')

        # Handle POST request logic if necessary

    if request.method == 'GET':
        EnquiryNumber = request.args.get('enq_id') if request.args.get('enq_id') else None
        selected_industry = request.args.getlist('selected_industry')
        selected_status = request.args.getlist('selected_checkboxes')
        selected_years = request.args.getlist('selected_years')
        selected_sites = request.args.getlist('selected_sites')
        selected_clients = request.args.getlist('selected_clients')

        status = None
        query = 'SELECT EnquiryNumber, RevisionNumber, Industry, Client, Name, Contact, Email, SiteOrEndUser, EnquiryReceived, SubmitBeforeDate, DateOfSubmission, Status, EstimateValue FROM enquiries WHERE 1=1'

        if EnquiryNumber is not None:
            query += f' AND EnquiryNumber = "{EnquiryNumber}"'
            selected_status = [ ]
            selected_industry = [ ]
            selected_years = [ ]
            selected_clients = [ ]
            selected_sites = [ ]

        else:

            # Status condition
            status_condition = None

            if selected_status:
                status_condition = ' OR '.join([f"(Status = '{status_value}')" for status_value in selected_status])

            # Year condition
            year_condition = None
            if selected_years:
                year_condition = ' OR '.join([f"(strftime('%Y', EnquiryReceived) = '{year}')" for year in selected_years])

            # Industry condition
            industry_condition = None
            if selected_industry:
                industry_condition = ' OR '.join([f"(Industry = '{industry}')" for industry in selected_industry])

            # Industry condition
            client_condition = None
            if selected_clients:
                client_condition = ' OR '.join([f"(Client = '{Client}')" for Client in selected_clients])

            # Industry condition
            site_condition = None
            if selected_sites:
                site_condition = ' OR '.join([f"(SiteOrEndUser = '{SiteOrEndUser}')" for SiteOrEndUser in selected_sites])

            # Constructing the final query with proper grouping
            conditions = []
            if status_condition:
                conditions.append(f"({status_condition})")
            if year_condition:
                conditions.append(f"({year_condition})")
            if industry_condition:
                conditions.append(f"({industry_condition})")
            if client_condition:
                conditions.append(f"({client_condition})")
            if site_condition:
                conditions.append(f"({site_condition})")

            if conditions:
                query += ' AND ' + ' AND '.join(conditions)



        search_values = [EnquiryNumber, 0, 0]
        query += " ORDER BY EnquiryNumber DESC"

        # print(query)

        cursor = db.execute(query)
        enquiries = cursor.fetchall()
        return render_template("admin_templates/projects/admin_enquiry.html",selected_years=selected_years,selected_industry=selected_industry,all_years=all_years,
                               selected_clients=selected_clients,selected_sites=selected_sites,selected_checkboxes=selected_status,current_date=current_date, enq_ids=enq_ids,search_values=search_values,
                               all_sites=all_sites,all_clients=all_clients,department_code=department_code, user=user, enquiries=enquiries)

def format_currency(value):
    try:
        # Convert the string to a float
        value = float(value)

        # Set the locale to the user's default locale
        locale.setlocale(locale.LC_ALL, '')

        # Format the float as currency without the currency symbol
        formatted_value = locale.format_string('%.*f', (locale.localeconv()['frac_digits'], value), grouping=True)

        return formatted_value

    except ValueError:
        # Handle the case where the input is not a valid float
        return value

@app.route('/admin_enquiry', methods=['POST', 'GET'])
@login_required
def admin_enquiry():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])

    db = get_database()
    cursor = db.cursor()
    file_path = None
    department_code = get_department_code_by_username( user['name'])
    cursor.execute('SELECT display_name FROM client_details')
    Cilent_suggestions = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]
    current_date = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT DISTINCT strftime("%Y", EnquiryReceived) as year FROM enquiries WHERE EnquiryReceived IS NOT NULL ORDER BY year DESC')
    all_years = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Client FROM enquiries WHERE Client IS NOT NULL')
    all_clients = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT DISTINCT SiteOrEndUser FROM enquiries WHERE SiteOrEndUser IS NOT NULL')
    all_sites = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT industry FROM industry')
    industry = sorted([row[0] for row in cursor.fetchall()])

    action = request.form.get('action', None)

    if request.method == 'POST':
        if action == 'create_project':
            enquiry_number = request.form.get('enquiry_number')
            return redirect(url_for('admin_create_project', enquiry_number=enquiry_number))
        else:
            industry = request.form.get('industry')
            contact = request.form.get('contact')
            status = request.form.get('status')
            eq = request.form.get('reference_number')
            # print("status:----- ",status)
            client = request.form.get('client')
            name = request.form.get('name')
            PhoneNumber = request.form.get('phone')
            # print("phone......",PhoneNumber)
            Email = request.form.get('email')
            site_or_end_user = request.form.get('site')
            received_date = request.form.get('received_date')
            submit_before_date = request.form.get('submission_date')
            date_of_submission = request.form.get('Date_Submission')
            revision_number = request.form.get('Revision_number')
            # estimate_value = request.form.get('Estimated_value')
            # print(".......estimate_value......",estimate_value)
            est_value = request.form.get('Estimated_value')
            estimate_value = format_currency(est_value)
            # print("Formatted Estimate Value: ", estimate_value)
            currency = request.form.get('currency')
            db.execute("INSERT INTO enquiries (EnquiryNumber,contact,Industry, Client, Name, SiteOrEndUser, EnquiryReceived, SubmitBeforeDate, DateOfSubmission, RevisionNumber, EstimateValue,status,PhoneNumber,Email,currency) VALUES (?,?,?,?,?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (eq,contact, industry, client, name, site_or_end_user, received_date, submit_before_date, date_of_submission, revision_number, estimate_value,status,PhoneNumber,Email, currency))
            db.commit()
            flash('Enquiry added successfully', 'success')
            return redirect(url_for('admin_enquiry'))

    cursor = db.execute('SELECT * FROM enquiries ORDER BY EnquiryNumber DESC LIMIT 50')
    enquiries = cursor.fetchall()
    cursor = db.execute("SELECT MAX(EnquiryNumber) FROM enquiries")
    last_enquiry_number = cursor.fetchone()[0]
    next_enquiry_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1
    search_values = [0,0,'']
    return render_template("admin_templates/projects/admin_enquiry.html",all_years=all_years,current_date=current_date,enq_ids=enq_ids,search_values=search_values,
                           is_pm=is_pm,user = user,department_code=department_code, enquiries=enquiries, file_path=file_path, next_enquiry_number=next_enquiry_number,
                           industry = industry, all_sites=all_sites,all_clients=all_clients,Cilent_suggestions=Cilent_suggestions)

@app.route('/admin_edit_enquiry', methods=['POST', 'GET'])
@login_required
def admin_edit_enquiry():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username( user['name'])
    cursor.execute('SELECT display_name FROM client_details')
    Cilent_suggestions = sorted([row[0] for row in cursor.fetchall()])
    search_values = [0,0,0]
    current_date = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT DISTINCT strftime("%Y", EnquiryReceived) as year FROM enquiries WHERE EnquiryReceived IS NOT NULL ORDER BY year DESC')
    all_years = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Client FROM enquiries WHERE Client IS NOT NULL')
    all_clients = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT DISTINCT SiteOrEndUser FROM enquiries WHERE SiteOrEndUser IS NOT NULL')
    all_sites = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT industry FROM industry')
    industry = sorted([row[0] for row in cursor.fetchall()])

    action = request.form.get('action', None)

    if request.method == 'GET':
        enquiry_number = request.args.get('enquiry_number')
        cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (enquiry_number,))
        enquiry = cursor.fetchone()
        if enquiry is None:
            flash('Enquiry not found', 'error')
            return redirect(url_for('admin_enquiry'))
        cursor = db.execute('SELECT * FROM enquiries ORDER BY EnquiryNumber DESC LIMIT 50')
        enquiries = cursor.fetchall()
        user = get_current_user()

        return render_template("admin_templates/projects/admin_edit_enquiry.html",all_years=all_years,all_clients=all_clients,all_sites=all_sites,
                               current_date=current_date,search_values=search_values,Cilent_suggestions=Cilent_suggestions,is_pm=is_pm,enq_ids=enq_ids,
                               industry = industry, department_code=department_code,enquiries=enquiries, enquiry=enquiry,user=user)

    if request.method == 'POST':
        if action == 'create_project':
            enquiry_number = request.form.get('enquiry_number')
            if enquiry_number and enquiry_number.isdigit():
                enquiry_number = int(enquiry_number)
                return redirect(url_for('admin_create_project', is_pm=is_pm,enquiry_number=enquiry_number))
            else:
                return "Invalid or missing enquiry number"
        else:
            industry = request.form.get('industry')
            contact = request.form.get('contact')
            eq = request.form.get('reference_number')
            Update_Status = request.form.get('status')
            client = request.form.get('client')
            name = request.form.get('name')
            PhoneNumber = request.form.get('phone')
            Email = request.form.get('email')
            site_or_end_user = request.form.get('site')
            received_date = request.form.get('received_date')
            submit_before_date = request.form.get('submission_date')
            date_of_submission = request.form.get('Date_Submission')
            revision_number = request.form.get('Revision_number')
            est_value = request.form.get('Estimated_value')
            estimate_value = format_currency(est_value)
            current_status = request.form.get('current_status')
            currency = request.form.get('currency')
            if Update_Status == "sairam":
                status = current_status

            else:
                status = Update_Status

            try:
                db.execute("UPDATE enquiries SET contact=?, Industry=?, Client=?, Name=?, SiteOrEndUser=?, EnquiryReceived=?, SubmitBeforeDate=?, DateOfSubmission=?, RevisionNumber=?, EstimateValue=?, status=?,PhoneNumber=?,Email=?,currency=? WHERE EnquiryNumber = ?",
                (contact, industry, client, name, site_or_end_user, received_date, submit_before_date, date_of_submission, revision_number, estimate_value, status,PhoneNumber,Email,currency, eq))
                db.commit()  # Commit the transaction
            except Exception as e:
                print("Error:", str(e))

            flash('Enquiry added successfully', 'success')
            cursor = db.execute("SELECT * FROM enquiries ORDER BY EnquiryNumber DESC LIMIT 50")
            enquiries = cursor.fetchall()
            cursor = db.execute('SELECT * FROM enquiries ORDER BY EnquiryNumber DESC')
            last_enquiry_number = cursor.fetchone()[0]
            next_enquiry_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1

            return render_template("admin_templates/projects/admin_enquiry.html",all_years=all_years,current_date=current_date,search_values=search_values,enq_ids=enq_ids,
                                   Cilent_suggestions=Cilent_suggestions, user=user,is_pm=is_pm,department_code=department_code,enquiries=enquiries,
                                   industry = industry,all_sites=all_sites,all_clients=all_clients,next_enquiry_number=next_enquiry_number)

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
        projectId = request.form['id']
        # print(projectId)
        client = request.form['client']
        projectName = request.form['name']
        startTime = request.form['start_time']
        endTime = request.form['end_time']
        status = request.form['status']
        po_number = request.form['po_number']
        pm = request.form['projectmanager']
        pe = request.form['projectengineer']
        type = request.form['Type']

        db = get_database()
        cursor = db.cursor()

        # Check if the project with the given ID exists
        cursor.execute('SELECT id FROM projects WHERE id = ?', [projectId])
        existing_project = cursor.fetchone()

        if existing_project:
            # Update existing project
            cursor.execute('''
                UPDATE projects
                SET client=?, project_name=?, start_time=?, end_time=?, status=?, po_number=?, pm=?, pe=?, type=?
                WHERE id=?
            ''', [client, projectName, startTime, endTime, status, po_number, pm, pe, type, projectId])

            # flash(f"'{projectId}' is already Exits.", 'error')
            # Assuming your 'admin_create_project' endpoint requires the 'enquiry_number' parameter
            # return redirect(url_for('admin_create_project', enquiry_number=projectId))

            # return redirect(url_for('admin_create_project'))
        else:
            # Insert a new row
            cursor.execute('''
                INSERT INTO projects (id, client, project_name, start_time, end_time, status, po_number, pm, pe)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', [projectId, client, projectName, startTime, endTime, status, po_number, pm, pe])
            cursor.execute(''' UPDATE enquiries SET status = 'Won' WHERE EnquiryNumber = ?''', [projectId])

        db.commit()
        return redirect(url_for('admin_dashboard_page'))

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
        return redirect(url_for('admin_dashboard_page'))
    return render_template('admin_dashboard_page.html', user=user)

@app.route('/create_project_allocate_hours/<int:EnquiryNumber>', methods=['POST', 'GET'])
@login_required
def create_project_allocate_hours(EnquiryNumber):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    db = get_database()
    data = request.form.to_dict()
    cursor = db.cursor()
        # Check if EnquiryNumber exists in projects table
    cursor.execute("SELECT 1 FROM projects WHERE id = ?", (EnquiryNumber,))
    existing_project = cursor.fetchone()

    if not existing_project:
        flash("Please create a project before allocating hours.", "error")
        return redirect(url_for('admin_create_project', enquiry_number=EnquiryNumber))

    for code, hours in data.items():
        if hours.strip():  # Check if it's not an empty or whitespace-only string
            hours_float = float(hours)
        else:
            # Handle the case where hours is empty or contains only whitespace
            hours_float = 0.0

        cursor.execute("SELECT 1 FROM pmtable WHERE department_code = ? AND project_id = ?", (code, EnquiryNumber))
        existing_record = cursor.fetchone()

        if existing_record:
            # Update the existing record
            cursor.execute("UPDATE pmtable SET added_hours = added_hours + ?, total = total + ? WHERE project_id = ? AND department_code = ?", (hours_float, hours_float, EnquiryNumber, code))
        else:
            # Insert a new record
            cursor.execute("INSERT INTO pmtable (project_id, department_code, hours, added_hours, total) VALUES (?, ?, ?, ?, ?)", (EnquiryNumber, code, hours_float, 0.0, hours_float))

        db.commit()
    return redirect(url_for('admin_create_project', enquiry_number=EnquiryNumber))

@app.route('/admin_view_all_employees', methods=['GET', 'POST'])
@login_required
def admin_view_all_employees():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    cursor = db.cursor()
    current_year = datetime.now().year
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]
    data = []
    last_day = None
    start_day = None
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        if employee_id:
        # Redirect to admin_view_all_employees
            return redirect(url_for('admin_employee_view_data'))
        month = request.form.get('month')
        year = request.form.get('year')
        workingDate = f"{month} {year}"
        nyear = int(year)
        nmonth = int(month)
        month_name = calendar.month_name[nmonth]
        start_date = datetime(nyear, nmonth, 1)
        start_day = start_date.weekday()
        last_day = monthrange(nyear, nmonth)[1] if nyear and nmonth else None
        # print("workingDate:-",workingDate)
        cursor.execute('SELECT DISTINCT employeeID FROM workingHours WHERE substr(workingDate, 4) = ?', (workingDate,))
        employee_ids = [row[0] for row in cursor.fetchall()]
        all_employee_data = []
        date_total_hours = {}
        for employee_id in employee_ids:
            cursor.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ? AND workingDate LIKE ?', (employee_id, f'%{workingDate}',))
            raw_data = cursor.fetchall()
            # print(f"Raw data for employee {employee_id} before processing: {raw_data}")
            employee_hours = {}
            total_hours = 0
            for entry in raw_data:
                working_date = entry['workingDate'].split()[0][-2:]
                hours_worked = entry['hoursWorked']
                # print(f"Working date: {working_date}, Hours worked: {hours_worked}")
                if isinstance(hours_worked, str) and hours_worked.isdigit():
                    hours_worked = int(hours_worked)
                # Accumulate hours for each date
                if working_date not in employee_hours:
                    employee_hours[working_date] = 0
                employee_hours[working_date] += hours_worked
                total_hours += hours_worked
                date_total_hours[working_date] = date_total_hours.get(working_date, 0) + hours_worked
            # print(f"Processed data for employee {employee_id}: {employee_hours}")
            employee_data = {'employee_id': employee_id, 'data': [{'date': date, 'hours_worked': hours} for date, hours in employee_hours.items()], 'total_hours': total_hours}
            all_employee_data.append(employee_data)
        total_hours_all_employees = sum(entry['total_hours'] for entry in all_employee_data)

        return render_template("admin_templates/projects/admin_view_all_employees.html", user=user, usernames=usernames,date_total_hours=date_total_hours,total_hours_all_employees=total_hours_all_employees,
                               current_year=nyear, all_employee_data=all_employee_data, selected_month=month_name,department_code=department_code,is_pm=is_pm,
                               last_day=last_day, month=nmonth, start_day=start_day, employee_id=None)

    # print("...............................nonselecton........not post.................")
    current_year = datetime.now().year
    current_month = datetime.now().month
    workingDate = f"{current_month} {current_year}"
    nyear = int(current_year)
    nmonth = int(current_month)
    month_name = calendar.month_name[nmonth]
    start_date = datetime(nyear, nmonth, 1)
    start_day = start_date.weekday()
    last_day = monthrange(nyear, nmonth)[1] if nyear and nmonth else None
    cursor.execute('SELECT DISTINCT employeeID FROM workingHours WHERE substr(workingDate, 4) = ?', (workingDate,))
    employee_ids = [row[0] for row in cursor.fetchall()]
    all_employee_data = []
    date_total_hours = {}


    for employee_id in employee_ids:
        cursor.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ? AND workingDate LIKE ?', (employee_id, f'%{workingDate}',))
        raw_data = cursor.fetchall()
        # print(f"Raw data for employee {employee_id} before processing: {raw_data}")
        employee_hours = {}
        total_hours = 0
        for entry in raw_data:
            working_date = entry['workingDate'].split()[0][-2:]
            hours_worked = entry['hoursWorked']
            # print(f"Working date: {working_date}, Hours worked: {hours_worked}")
            if isinstance(hours_worked, str) and hours_worked.isdigit():
                hours_worked = int(hours_worked)
            # Accumulate hours for each date
            if working_date not in employee_hours:
                employee_hours[working_date] = 0
            employee_hours[working_date] += hours_worked
            total_hours += hours_worked
            date_total_hours[working_date] = date_total_hours.get(working_date, 0) + hours_worked
        # print(f"Processed data for employee {employee_id}: {employee_hours}")
        employee_data = {'employee_id': employee_id, 'data': [{'date': date, 'hours_worked': hours} for date, hours in employee_hours.items()], 'total_hours': total_hours}
        all_employee_data.append(employee_data)

    total_hours_all_employees = sum(entry['total_hours'] for entry in all_employee_data)


    date_total_hours = {}
    for entry in all_employee_data:
        for day_entry in entry['data']:
            date = day_entry['date']
            hours_worked = day_entry['hours_worked']
            date_total_hours[date] = date_total_hours.get(date, 0) + hours_worked

    return render_template("admin_templates/projects/admin_view_all_employees.html", user=user, usernames=usernames,date_total_hours=date_total_hours,total_hours_all_employees=total_hours_all_employees,
                           current_year=nyear, all_employee_data=all_employee_data, selected_month=month_name,department_code=department_code,is_pm=is_pm,
                           last_day=last_day, month=nmonth, start_day=start_day, employee_id=None)


from datetime import datetime

@app.route('/view_by_project_working_hours', methods=['GET', 'POST'])
@login_required
def view_by_project_working_hours():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    cursor = db.cursor()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    cursor.execute('SELECT username FROM admin_user')
    usernames = [row[0] for row in cursor.fetchall()]

    if request.method == 'POST':
        project_id1 = request.form.get('project_id')
        employee = request.form.get('employee_id')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        query = "SELECT * FROM projects WHERE id = ?"
        db = get_database()
        cursor = db.cursor()
        cursor.execute(query, [project_id1])
        project_details = cursor.fetchone()
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        date_range = start_date_str + " To " + end_date_str

        if not project_id1:
            query = """
                SELECT * FROM workingHours
                WHERE employeeID = ? AND workingDate BETWEEN ? AND ?
            """
            working_hours_cur = db.execute(query, [employee, start_date, end_date])

                        # Calculate total working hours
            total_hours_query = """
                SELECT SUM(hoursWorked) FROM workingHours
                WHERE employeeID = ? AND workingDate BETWEEN ? AND ?
            """
            total_hours_cur = db.execute(total_hours_query, [project_id1, employee, start_date, end_date])
            total_hours = total_hours_cur.fetchone()[0] or 0  # Get the total hours, default to 0 if None
        else:
            # Fetch data based on conditions
            query = """
                SELECT * FROM workingHours
                WHERE projectID = ? AND employeeID = ? AND workingDate BETWEEN ? AND ?
            """
            working_hours_cur = db.execute(query, [project_id1, employee, start_date, end_date])

            # Calculate total working hours
            total_hours_query = """
                SELECT SUM(hoursWorked) FROM workingHours
                WHERE projectID = ? AND employeeID = ? AND workingDate BETWEEN ? AND ?
            """
            total_hours_cur = db.execute(total_hours_query, [project_id1, employee, start_date, end_date])
            total_hours = total_hours_cur.fetchone()[0] or 0  # Get the total hours, default to 0 if None

        working_hours_data = working_hours_cur.fetchall()

        print("Working Hours Data:", working_hours_data)

        return render_template("admin_templates/projects/view_by_project_working_hours.html",total_hours=total_hours,
                            project_ids=project_ids, user=user, usernames=usernames,project_id1=project_id1,employee_id=employee,start_date=start_date,end_date=end_date,project_details=project_details,
                            range= date_range,working_hours_data=working_hours_data, department_code=department_code, is_pm=is_pm)

    return render_template("admin_templates/projects/view_by_project_working_hours.html",
                               project_ids=project_ids, user=user, usernames=usernames,department_code=department_code, is_pm=is_pm)

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

@app.route('/delete_do_item/<int:id>', methods=["GET", "POST"])
@login_required
def delete_do_item(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        i = request.args.get('i', type=int)
        db.execute("DELETE FROM do_items WHERE id = ?", (id,))
        cursor.execute("SELECT * FROM do_items")
        items = cursor.fetchall()
        department_code = get_department_code_by_username(user['name'])
        is_pm = is_pm_for_project(user['name'])
        project_id = request.args.get('p', type=int)
        cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        project_details = cursor.fetchone()
        cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
        enquiries_details = cursor.fetchone()
        from datetime import datetime
        current_date = datetime.now()
        formatted_date = current_date.strftime("%d %m %y")
        cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
        created_do = cursor.fetchall()
        print(request.form)

        do_number_variable = request.args.get('d')
        print(do_number_variable)
        db.commit()

        if i == 1:
            return render_template('admin_templates/projects/project_do.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                            form_data=dict(),user=user, project_id=project_id, project_details=project_details,created_do=created_do,do_number_variable=do_number_variable)
        elif i == 2:
            return render_template('admin_templates/projects/project_do_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                           form_data=dict(), user=user, project_id=project_id, project_details=project_details,created_do=created_do,do_number_variable=do_number_variable)
    return render_template('project_do.html', user=user)

@app.route('/project_do_edit', methods=['GET', 'POST'])
@login_required
def project_do_edit():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    do_number_variable = request.args.get('do_id')
    project_id = request.args.get('proj_no', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM do_items")
    items = cursor.fetchall()

    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
    created_do = cursor.fetchall()

    if request.method == 'POST':
        item = request.form.get('item')
        uom = request.form.get('uom')
        quantity = request.form.get('quantity')
        project_id = request.form.get('project_id1', type=int)
        do_number = request.form.get('do_number')
        sub_item = request.form.get('sub_item')

        if 'action' in request.form and request.form['action'] == 'project_do_edit':

            if 'sub_item' in request.form:
                sub_item = request.form.get('sub_item')
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            else:
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity) VALUES (?, ?, ?, ?, ?)", (project_id, do_number, item, uom, quantity))

            # Fetch items after adding to display in the template
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()

            return render_template('admin_templates/projects/project_do_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do)

        elif 'action' in request.form and request.form['action'] == 'add_sub_item':
            sub_item = request.form.get('sub_item')
            cursor = db.cursor()
            cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()
            return render_template('admin_templates/projects/project_do_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(item=item, uom=uom, quantity=quantity, sub_item=sub_item),created_do=created_do)

    return render_template('admin_templates/projects/project_do_edit.html',current_date=formatted_date,enquiries_details=enquiries_details,is_pm=is_pm, department_code=department_code,items=items,
                          do_number_variable=do_number_variable, user=user, project_id=project_id,project_details=project_details,form_data=dict(),created_do=created_do)

@app.route('/project_do', methods=['GET', 'POST'])
@login_required
def project_do():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    project_id = request.args.get('project_id', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM do_items")
    items = cursor.fetchall()

    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
    created_do = cursor.fetchall()
    current_year = datetime.now().strftime("%y")

    cursor = db.execute("SELECT MAX(id) FROM created_do")
    cursor.execute("SELECT SUBSTR(do_number, -4) as last_digits FROM created_do WHERE id = (SELECT MAX(id) FROM created_do)")
    result = cursor.fetchone()

    # Extract the value from the 'last_digits' column
    last_enquiry_number = int(result['last_digits']) if result else 0

    # last_enquiry_number = cursor.fetchone()[0]
    # print(".........last_enquiry_number",last_enquiry_number)
    sequential_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1

    formatted_sequential_number = f"{sequential_number:04}"
    do_number_variable = f"D-{current_year}-{formatted_sequential_number}"
    # print(do_number_variable)

    if request.method == 'POST':
        item = request.form.get('item')
        uom = request.form.get('uom')
        quantity = request.form.get('quantity')
        project_id = request.form.get('project_id1', type=int)
        do_number = request.form.get('do_number')
        sub_item = request.form.get('sub_item')

        if 'action' in request.form and request.form['action'] == 'project_do':

            if 'sub_item' in request.form:
                sub_item = request.form.get('sub_item')
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            else:
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity) VALUES (?, ?, ?, ?, ?)", (project_id, do_number, item, uom, quantity))

            # Fetch items after adding to display in the template
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
            created_do = cursor.fetchall()
            cursor = db.execute("SELECT MAX(id) FROM created_do")
            cursor.execute("SELECT SUBSTR(do_number, -4) as last_digits FROM created_do WHERE id = (SELECT MAX(id) FROM created_do)")
            result = cursor.fetchone()

            # Extract the value from the 'last_digits' column
            last_enquiry_number = int(result['last_digits']) if result else 0

            # last_enquiry_number = cursor.fetchone()[0]
            # print(".........last_enquiry_number",last_enquiry_number)
            sequential_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1

            formatted_sequential_number = f"{sequential_number:04}"
            do_number_variable = f"D-{current_year}-{formatted_sequential_number}"
            # print(do_number_variable)
            db.commit()

            return render_template('admin_templates/projects/project_do.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                               user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do,do_number_variable=do_number_variable)

        elif 'action' in request.form and request.form['action'] == 'add_sub_item':
            sub_item = request.form.get('sub_item')
            cursor = db.cursor()
            cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
            created_do = cursor.fetchall()
            cursor = db.execute("SELECT MAX(id) FROM created_do")
            cursor.execute("SELECT SUBSTR(do_number, -4) as last_digits FROM created_do WHERE id = (SELECT MAX(id) FROM created_do)")
            result = cursor.fetchone()

            # Extract the value from the 'last_digits' column
            last_enquiry_number = int(result['last_digits']) if result else 0

            # last_enquiry_number = cursor.fetchone()[0]
            print(".........last_enquiry_number",last_enquiry_number)
            sequential_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1

            formatted_sequential_number = f"{sequential_number:04}"
            do_number_variable = f"D-{current_year}-{formatted_sequential_number}"
            print(do_number_variable)
            db.commit()
            return render_template('admin_templates/projects/project_do.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                               user=user, project_id=project_id, project_details=project_details,form_data=dict(item=item, uom=uom, quantity=quantity, sub_item=sub_item),created_do=created_do,do_number_variable=do_number_variable)

    return render_template('admin_templates/projects/project_do.html',current_date=formatted_date,enquiries_details=enquiries_details,is_pm=is_pm, department_code=department_code,items=items,
                           user=user, project_id=project_id,project_details=project_details,form_data=dict(),created_do=created_do,do_number_variable=do_number_variable)

@app.route('/project_po_edit', methods=['GET', 'POST'])
@login_required
def project_po_edit():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    do_number_variable = request.args.get('po_id')
    project_id = request.args.get('proj_no', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM po_items")
    items = cursor.fetchall()

    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
    created_po = cursor.fetchall()

    if request.method == 'POST':
        item = request.form.get('item')
        uom = request.form.get('uom')
        quantity = request.form.get('quantity')
        project_id = request.form.get('project_id1', type=int)
        do_number = request.form.get('do_number')
        sub_item = request.form.get('sub_item')

        if 'action' in request.form and request.form['action'] == 'project_do_edit':

            if 'sub_item' in request.form:
                sub_item = request.form.get('sub_item')
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            else:
                cursor = db.cursor()
                cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity) VALUES (?, ?, ?, ?, ?)", (project_id, do_number, item, uom, quantity))

            # Fetch items after adding to display in the template
            cursor.execute("SELECT * FROM do_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()

            return render_template('admin_templates/projects/project_po_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do)

        elif 'action' in request.form and request.form['action'] == 'add_sub_item':
            sub_item = request.form.get('sub_item')
            cursor = db.cursor()
            cursor.execute("INSERT INTO do_items (project_id, do_number, item, uom, quantity,sub_item) VALUES (?, ?, ?,?, ?,?)", (project_id, do_number, item, uom, quantity,sub_item))
            cursor.execute("SELECT * FROM po_items")
            items = cursor.fetchall()
            department_code = get_department_code_by_username(user['name'])
            is_pm = is_pm_for_project(user['name'])
            project_id = request.form.get('project_id1', type=int)
            cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            project_details = cursor.fetchone()
            cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
            enquiries_details = cursor.fetchone()
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d %m %y")
            cursor = db.execute('SELECT * FROM created_po ORDER BY id DESC')
            created_do = cursor.fetchall()
            do_number_variable = request.args.get('do_number')
            db.commit()
            return render_template('admin_templates/projects/project_po_edit.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                              do_number_variable=do_number, user=user, project_id=project_id, project_details=project_details,form_data=dict(item=item, uom=uom, quantity=quantity, sub_item=sub_item),created_do=created_do)

    return render_template('admin_templates/projects/project_po_edit.html',current_date=formatted_date,enquiries_details=enquiries_details,is_pm=is_pm, department_code=department_code,items=items,
                          do_number_variable=do_number_variable, user=user, project_id=project_id,project_details=project_details,form_data=dict(),created_po=created_po)

@app.route('/deletepo/<int:poid>', methods=["GET", "POST"])
@login_required
def deletepo(poid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM created_po WHERE id = ?', [poid])
        db.commit()
        return redirect(url_for('project_po'))
    return render_template('project_po.html', user=user)

@app.route('/delete_po_item/<int:id>', methods=["GET", "POST"])
@login_required
def delete_po_item(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute("DELETE FROM po_items WHERE id = ?", (id,))
        db.commit()
        return redirect(url_for('project_po'))
    return render_template('project_po.html', user=user)



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

        # Fetch all created PR records
    project_id = request.args.get('project_id', type=int)
    cursor = db.execute('SELECT * FROM created_po WHERE project_id = ? ORDER BY id DESC',(project_id,))
    created_po = cursor.fetchall()
    # Initialize an empty DataFrame to store the main data
    rows = []
    # Loop through each PR in created_pr
    for po in created_po:
        po_id =         po[0]
        po_no =         po[1]
        po_date =       po[5]
        project_id=     po[2]
        supplier_name = po[3]
        created_by =    po[6]
        status =        po[14]
        Code =          po[8]

        # Fetch items for the current PR from pr_items table
        cursor.execute('SELECT item, quantity, uom, Unit_Price, total FROM po_items WHERE po_number = ?', (po_no,))
        items = cursor.fetchall()

        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'Description': item[0], 'QTY': item[1], 'UOM': item[2], 'Unit_Price': item[3], 'Total_Price': item[4] })
        total_price_sum1 = round(sum([float(item[4]) for item in items]), 2)
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)

        # Append the main row to the rows list
        rows.append({ 'ID': po_id,'PR_Date': po_date, 'PR_no': po_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    # Convert rows to a pandas DataFrame
    grouped_df = pd.DataFrame(rows)

    return render_template('admin_templates/projects/project_po.html',is_pm=is_pm, department_code=department_code, created_po=created_po,user=user, project_id=project_id,grouped_df=grouped_df)

@app.route('/pr_item', methods=['GET', 'POST'])
@login_required
def pr_item():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

    project_id = request.args.get('project_id', type=int)
    PR_no = None
    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])

    if request.method == 'POST':
        action = request.form.get('action')
        project_id = request.form.get('project_id', type=int)
        PR_no = request.form.get('PR_no')

        if action == 'generate_pr':

            project_id = request.form.get('project_id')
            pr_number = request.form.get('PR_no')
            gst_checkbox = request.form.get('gstCheckbox')
            part_nos = request.form.getlist('part_no[]')
            descriptions = request.form.getlist('description[]')
            uoms = request.form.getlist('uom[]')
            quantities = request.form.getlist('quantity[]')
            unit_prices = request.form.getlist('unit_price[]')
            items = []

            for part_no, description, uom, quantity, unit_price in zip(part_nos, descriptions, uoms, quantities, unit_prices):
                total = float(quantity) * float(unit_price)
                rounded_total = round(total, 2)
                item = { 'project_id': project_id,'pr_number': pr_number, 'part_no': part_no, 'description': description, 'uom': uom, 'quantity': float(quantity), 'unit_price': float(unit_price), 'total': rounded_total }
                if gst_checkbox:
                    item['gst'] = 1
                else:
                    item['gst'] = 0
                items.append(item)

            print("\n",items)

            if items:

                for item in items:
                    cursor.execute("""INSERT INTO pr_items (project_id, pr_number, Part_No, item, quantity, uom, Unit_Price, GST, total)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (item['project_id'], item['pr_number'], item['part_no'], item['description'], item['quantity'], item['uom'], item['unit_price'], item['gst'], item['total'] ))

                # Update the status of the PR
                if department_code <= 1001:
                    cursor.execute("UPDATE created_pr SET status = 'Approved' WHERE PR_no = ?", (PR_no,))
                    cursor.execute("UPDATE created_pr SET approved_by = ? WHERE PR_no = ?", (user['name'], PR_no))
                else:
                    cursor.execute("UPDATE created_pr SET status = 'Created' WHERE PR_no = ?", (PR_no,))
                flash('PR generated successfully! Please wait for Approval.', 'pr_genrated')
            else:
                cursor.execute("DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?", (PR_no, project_id))
                db.commit()

            # After committing, fetch updated items and header details
            cursor.execute("SELECT MAX(id) FROM created_pr")
            result = cursor.fetchone()

            if result and result[0] is not None:
                max_pr = int(result[0])
            else:
                max_pr = 0
            sequential_number = max_pr + 1
            PR_no = f"{project_id}-ExpensesCode-{sequential_number:04}"

            cursor.execute('SELECT display_name FROM vendors_details')
            Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

            cursor.execute("SELECT * FROM pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
            items = cursor.fetchall()
            print('..........PR_no.................',PR_no)
            cursor.execute("SELECT * FROM created_pr where PR_no = ?", (PR_no,))
            header_details = cursor.fetchone()
            print('..........header_details.................',header_details)
            db.commit()
            item = None
            from datetime import datetime
            current_date = datetime.now()
            formatted_date = current_date.strftime("%d-%m-%y")
            return render_template('admin_templates/projects/project_pr.html', current_date=formatted_date, is_pm=is_pm, department_code=department_code,usernames=usernames,
                          item=item, items=items, header_details=header_details, Supplier_Names=Supplier_Names, PR_no=PR_no, user=user, project_id=project_id)

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
                status = 'Approved' if department_code <= 1001 else 'Created'
                cursor.execute("UPDATE created_pr SET status = ? WHERE PR_no = ?", (status, pr_number))
                from datetime import datetime
                current_date = datetime.now()
                formatted_date = current_date.strftime("%d-%m-%y")
                cursor.execute('''UPDATE created_pr SET PR_no = ?, PR_Date = ?  WHERE PR_no = ?''',  (New_PR_no, formatted_date, pr_number))
                db.commit()

            else:
                cursor.execute("DELETE FROM created_pr WHERE PR_no = ? AND project_id = ?", (pr_number, project_id))
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

                # Fetch items for the current PR from pr_items table
                cursor.execute('SELECT id, item, quantity, uom, Unit_Price, total FROM pr_items WHERE pr_number = ?', (pr_no,))
                items = cursor.fetchall()

                # Prepare aggregated values as a list of dictionaries (for sub_df)
                sub_df_data = []
                for item in items:
                    sub_df_data.append({ 'ID': item[0], 'Description': item[1], 'QTY': item[2], 'UOM': item[3], 'Unit_Price': item[4], 'Total_Price': item[5] })
                total_price_sum = sum([float(item[5]) for item in items])
                # Append the main row to the rows list
                rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                    'Sub_DF': pd.DataFrame(sub_df_data) })

            # Convert rows to a pandas DataFrame
            grouped_df = pd.DataFrame(rows)

            return render_template('admin_templates/projects/pr_view.html', grouped_df=grouped_df, user=user,project_id=project_id, department_code=department_code, is_pm=is_pm)

        # After committing, fetch updated items and header details
        cursor.execute("SELECT * FROM temp_pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
        items = cursor.fetchall()

        cursor.execute("SELECT * FROM created_pr where PR_no = ?", (PR_no,))
        header_details = cursor.fetchone()
        item = 'show'

    else:
        # Fetch items and header details for initial rendering (GET request)
        cursor.execute("SELECT * FROM temp_pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
        items = cursor.fetchall()

        header_details = None
        item = None

    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")

    return render_template('admin_templates/projects/project_pr.html', current_date=formatted_date, is_pm=is_pm, department_code=department_code,usernames=usernames,
                          item=item, items=items, header_details=header_details, Supplier_Names=Supplier_Names, PR_no=PR_no, user=user, project_id=project_id)

@app.route('/project_pr', methods=['GET', 'POST'])
@login_required
def project_pr():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    # Get projectId from query parameters
    project_id = request.args.get('project_id', type=int)
    cursor = db.cursor()
    # Fetch existing items and header details
    cursor.execute("SELECT MAX(id) FROM created_pr")
    result = cursor.fetchone()
    if result and result[0] is not None:
        max_pr = int(result[0])
    else:
        max_pr = 0
    sequential_number = max_pr + 1
    PR_no = f"{project_id}-ExpensesCode-{sequential_number:04}"

    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute("SELECT * FROM pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
    items = cursor.fetchall()

    cursor.execute("SELECT * FROM created_pr where PR_no = ?", (PR_no,))
    header_details = cursor.fetchone()

    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])

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
            print("................Old_PR_no..............",Old_PR_no)
            print("................New_PR_no..............",New_PR_no)
            print("................project_id..............",project_id)
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
            # Update the created_pr table with updated header details
            cursor.execute(''' UPDATE created_pr SET PR_no = ?, Supplier_Name = ?, Attn = ?,  phone_number = ?, PR_Date = ?, Quote_Ref = ?,  Delivery = ?, Address_Line1 = ?,  Address_Line2 = ?,  Payment_Terms = ?,
                    Currency = ?, comments = ?,  Supplier_address1 = ?,  Supplier_address2 = ?,  Supplier_address3 = ?,  Company_name = ?,  leat_time = ?, created_by=? WHERE id = ? ''',
                    ( New_PR_no, Supplier_Name, Attn, phone_number, PR_Date, Quote_Ref, Delivery,  Address_Line1, Address_Line2,  Payment_Terms,
                    Currency, comments,  Supplier_address1, Supplier_address2, Supplier_address3,  Company_name,  leat_time, Contact, header_id ))

            cursor.execute(''' UPDATE pr_items SET pr_number = ? WHERE pr_number = ? ''', (New_PR_no, Old_PR_no))
            flash('PR Header Updated successfully!', 'pr_header_success')

            cursor.execute("SELECT * FROM created_pr where PR_no = ?", (New_PR_no,))
            header_details = cursor.fetchone()
            cursor.execute('SELECT display_name FROM vendors_details')
            Supplier_Names = sorted([row[0] for row in cursor.fetchall()])
            cursor.execute('SELECT username FROM admin_user')
            usernames = sorted([row[0] for row in cursor.fetchall()])
            cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (New_PR_no,))
            pr_items = cursor.fetchall()
            db.commit()

            return render_template('admin_templates/projects/pr_edit.html',project_id=project_id1,pr_items=pr_items,Supplier_Names=Supplier_Names,usernames=usernames,
                                   New_PR_no=New_PR_no,user=user,department_code=department_code,header_details=header_details, is_pm=is_pm)

        if action == 'add_header':

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
            Quote_Ref = request.form.get('Quote_Ref')
            Expenses = request.form.get('code_number')
            temp_PR_no = request.form.get('PR_no')
            comments = request.form.get('comments')
            parts = temp_PR_no.split('-')
            if len(parts) == 3:
                project_id1 = parts[0]
                serial_number1 = parts[2]
            else:
                # Handle incorrect format if needed  status
                pass
            PR_no = f"{project_id1}-{Expenses}-{serial_number1}"
            Delivery = request.form.get('Delivery')
            Address_Line1 = request.form.get('Address_Line1')
            Address_Line2 = request.form.get('Address_Line2')
            Payment_Terms = request.form.get('Payment_Terms').upper() if request.form.get('Payment_Terms') else None
            Currency = request.form.get('Currency').upper() if request.form.get('Currency') else None
            cursor.execute('''INSERT INTO created_pr (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, created_by, Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms, Currency,
                        Supplier_address1, Supplier_address2, Supplier_address3, Company_name, leat_time, comments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (PR_no, project_id, Supplier_Name, Attn, phone_number, PR_Date, Contact, Quote_Ref, Expenses, Delivery, Address_Line1, Address_Line2, Payment_Terms, Currency, Supplier_address1,
                            Supplier_address2, Supplier_address3, Company_name, leat_time, comments))
            db.commit()
            flash('PR Header updated successfully!', 'pr_headder_added')

            # After committing, fetch updated items and header details
            cursor.execute("SELECT * FROM pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
            items = cursor.fetchall()

            cursor.execute("SELECT * FROM created_pr where PR_no = ?", (PR_no,))
            header_details = cursor.fetchone()
            item = 'show'

    else:
        # Fetch items and header details for initial rendering (GET request)
        cursor.execute("SELECT * FROM pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
        items = cursor.fetchall()

        header_details = None  # Assuming no header details are fetched on initial load
        item = None  # Or set to 'none' if needed
    print("..iam here........")
    return render_template('admin_templates/projects/project_pr.html', usernames=usernames,current_date=formatted_date, is_pm=is_pm, department_code=department_code,
                          item=item, items=items, header_details=header_details, Supplier_Names=Supplier_Names, PR_no=PR_no, user=user, project_id=project_id)

@app.route('/pr_edit/<int:id>', methods=['GET', 'POST'])
@login_required
def pr_edit(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM created_pr where id = ?", (id,))
    header_details = cursor.fetchone()
    cursor.execute('SELECT display_name FROM vendors_details')
    Supplier_Names = sorted([row[0] for row in cursor.fetchall()])

    cursor.execute('SELECT username FROM admin_user')
    usernames = sorted([row[0] for row in cursor.fetchall()])
    print(".............id.........",id)
    cursor.execute("SELECT PR_no FROM created_pr where id = ?", (id,))
    prnumber = cursor.fetchone()[0]
    print(".............prnumber.........",prnumber)
    # Fetch pr_items associated with pr_number
    cursor.execute("SELECT * FROM pr_items WHERE pr_number = ?", (prnumber,))
    pr_items = cursor.fetchall()
    parts = prnumber.split('-')
    if len(parts) == 3:
        project_id = parts[0]
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d-%m-%y")


    # Regular expression to match PR number with optional suffix
    pattern = re.compile(r"(\d{4}-\d{4}-\d{4})(\((\d+)\))?$")
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
        New_PR_no = "Invalid PR number format"

    print(".............New_PR_no.........",New_PR_no)
    print(".............project_id.........",project_id)
    return render_template('admin_templates/projects/pr_edit.html',Supplier_Names=Supplier_Names,usernames=usernames, user=user,department_code=department_code,
                          New_PR_no=New_PR_no, current_date=formatted_date, project_id=project_id,pr_items=pr_items,header_details=header_details, is_pm=is_pm,)

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
        cursor.execute('SELECT id, item, quantity, uom, Unit_Price, total FROM pr_items WHERE pr_number = ?', (pr_no,))
        items = cursor.fetchall()

        # Prepare aggregated values as a list of dictionaries (for sub_df)
        sub_df_data = []
        for item in items:
            sub_df_data.append({ 'ID': item[0], 'Description': item[1], 'QTY': item[2], 'UOM': item[3], 'Unit_Price': item[4], 'Total_Price': item[5] })

        total_price_sum1 = round(sum([float(item[5]) for item in items]), 2)
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
        total_price_sum = locale.format_string("%0.2f", total_price_sum1, grouping=True)
        # Append the main row to the rows list
        rows.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum, 'Approved_by': Approved_by,
            'Sub_DF': pd.DataFrame(sub_df_data) })

    # Convert rows to a pandas DataFrame
    grouped_df = pd.DataFrame(rows)
    print(" ........grouped_df.............\n",grouped_df)

    if request.method == 'POST':
        Approve = request.form.get('Approve')
        Issued = request.form.get('Issued')
        Delete = request.form.get('Delete')
        Print = request.form.get('Print')
        project_id = request.args.get('project_id', type=int)
        Update = request.form.get('Update')
        print(".....update...................",Update)
        db = get_database()
        cursor = db.cursor()
        if Approve:
            cursor.execute('UPDATE created_pr SET status = ? WHERE id = ?', ('Pending', Approve))
            cursor.execute("UPDATE created_pr SET approved_by = ? WHERE id = ?", (user['name'], Approve))
        if Issued:
            cursor.execute('UPDATE created_pr SET status = ? WHERE id = ?', ('Issued', Issued))
        if Delete:
            cursor.execute('SELECT PR_no FROM created_pr WHERE id = ?', (Delete,))
            pr_no = cursor.fetchone()[0]
            cursor.execute('DELETE FROM created_pr WHERE id = ?', (Delete,))
            cursor.execute('DELETE FROM pr_items WHERE pr_number = ?', (pr_no,))
            db.commit()


        # Loop through each PR in created_pr
        cursor = db.execute('SELECT * FROM created_pr WHERE project_id = ? ORDER BY id DESC',(project_id,))
        created_pr = cursor.fetchall()
        rows1 = []
        for pr in created_pr:
            pr_id = pr[0]
            pr_no = pr[1]
            pr_date = pr[5]
            project_id = pr[2]
            supplier_name = pr[3]
            created_by = pr[6]
            status = pr[14]
            Code = pr[8]
            cursor.execute('SELECT id, item, quantity, uom, Unit_Price, total FROM pr_items WHERE pr_number = ?', (pr_no,))
            items = cursor.fetchall()

            sub_df_data = []
            for item in items:
                sub_df_data.append({ 'ID': item[0], 'Description': item[1], 'QTY': item[2], 'UOM': item[3], 'Unit_Price': item[4], 'Total_Price': item[5] })
            total_price_sum = sum([float(item[5]) for item in items])
            # Append the main row to the rows list
            rows1.append({ 'ID': pr_id,'PR_Date': pr_date, 'PR_no': pr_no, 'Code': Code, 'Project_ID': project_id,'Supplier': supplier_name, 'Created_By': created_by,'Status': status,'PR_Total': total_price_sum,
                'Sub_DF': pd.DataFrame(sub_df_data) })
            print("..........sub_df_data..........",sub_df_data)
        grouped_df1 = pd.DataFrame(rows1)
        db.commit()
        db.close()
        return render_template('admin_templates/projects/pr_view.html',grouped_df=grouped_df1, user=user,project_id=project_id, department_code=department_code, is_pm=is_pm)

    search_values = [0,0,'none']

    cursor.execute('SELECT PR_no FROM created_pr ORDER BY id DESC ')
    PR_Numbers = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT project_id FROM created_pr ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Expenses FROM created_pr ORDER BY id DESC')
    Expenses = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT Supplier_Name FROM created_pr ORDER BY id DESC')
    Supplier_Names = [row[0] for row in cursor.fetchall()]

    print(".........................",PR_Numbers,project_ids,Expenses,Supplier_Names)


    return render_template('admin_templates/projects/pr_view.html', grouped_df=grouped_df, user=user,project_id=project_id, department_code=department_code, is_pm=is_pm,
                           PR_Numbers=PR_Numbers,project_ids=project_ids,Expenses=Expenses,Supplier_Names=Supplier_Names,search_values=search_values)




@app.route('/project_inv', methods=['GET', 'POST'])
@login_required
def project_inv():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    project_id = request.args.get('projectId', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]

    return render_template('admin_templates/projects/project_inv.html', project_ids=project_ids,is_pm=is_pm, department_code=department_code, user=user, project_id=project_id,project_details=project_details)

@app.route('/project_details_page/<int:id>', methods=['GET', 'POST'])
@login_required
def project_details_page(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (id,))
    project_details = cursor.fetchone()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor_open = db.execute("SELECT claim_no FROM claimed_items WHERE projectid = ?", (id,))
    open_claims = cursor_open.fetchall()

    # Extract claim_no values into a list
    claim_nos = [claim[0] for claim in open_claims]
    # print("Claim Numbers:", claim_nos)

    claim_nos = list(set(claim_nos))
    print("Claim Numbers without duplicates:", claim_nos)


    # Import required library
    from collections import defaultdict

    # Define counters for approved and other counts
    approved_count = 0
    other_count = 0

    # Loop through each claim number
    for claim_no in claim_nos:
        # Execute SQL query to get the count of each status for the current claim number
        cursor_claim_status = db.execute("SELECT status, COUNT(*) FROM claims WHERE claim_id = ? GROUP BY status", (claim_no,))
        status_counts = {status: count for status, count in cursor_claim_status.fetchall()}

        # Increment the counts
        if "Approved" in status_counts:
            approved_count += status_counts["Approved"]

        # Increment other_count by the total count of statuses other than "Approved"
        other_count += sum(status_counts.values()) - status_counts.get("Approved", 0)

    # Print the counts
    print("Approved Count:", approved_count)
    print("Other Count:", other_count)

    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE project_id = ? AND status != 'Processed' ",(id,))
    PR_pending = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM created_pr WHERE project_id = ?",(id,))
    PR_count = cursor.fetchone()[0]

    return render_template('admin_templates/projects/project_details_page.html', project_ids=project_ids, is_pm=is_pm, department_code=department_code,PR_count=PR_count,
                           PR_pending=PR_pending,approved_count=approved_count,other_count=other_count,user=user, project_id=id, project_details=project_details)

@app.route('/delete_pr_item/<int:id>', methods=["GET", "POST"])
@login_required
def delete_pr_item(id):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        cursor = db.cursor()
        # Retrieve pr_no and project_id based on the id
        cursor.execute("SELECT pr_number, project_id FROM temp_pr_items WHERE id = ?", (id,))
        result = cursor.fetchone()
        if result:
            PR_no = result['pr_number']
            project_id = result['project_id']
        else:
            PR_no = None
            project_id = None
        cursor.execute("SELECT * FROM created_pr where PR_no = ?", (PR_no,))
        header_details = cursor.fetchone()
        cursor.execute("DELETE FROM temp_pr_items WHERE id = ?", (id,))
        department_code = get_department_code_by_username(user['name'])
        is_pm = is_pm_for_project(user['name'])
        cursor.execute('SELECT display_name FROM client_details')
        Supplier_Names = sorted([row[0] for row in cursor.fetchall()])
        cursor.execute("SELECT * FROM temp_pr_items where pr_number = ? AND project_id = ?", (PR_no, project_id))
        items = cursor.fetchall()
        db.commit()
        current_date = None
        item = 'show'
    return render_template('admin_templates/projects/project_pr.html', current_date=current_date,is_pm=is_pm,department_code=department_code, items=items,
                           item=item, header_details=header_details, Supplier_Names=Supplier_Names, PR_no=PR_no, user=user, project_id=project_id )



from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import Flask, render_template, request, redirect, url_for, session
from reportlab.lib.units import inch
from shareplum import Site
from shareplum import Office365
from io import BytesIO

def generate_delivery_order_pdf(do_number, do_date, proj_no, project_name, email, po_number, client, site, client_address_line_1, client_address_line_2, client_address_line_3, client_address_line_4,
                                site_address_line_1, site_address_line_2, site_address_line_3, site_address_line_4, items_list):

    # Format the do_number to make it suitable for a filename (remove invalid characters)
    do_number_for_filename = "".join(c for c in do_number if c.isalnum() or c in (' ', '_')).rstrip()

    # Construct the PDF filename
    pdf_filename = f'C:/Users/Hewlett Packard/Desktop/do/{do_number_for_filename}.pdf'

    c = canvas.Canvas(pdf_filename, pagesize=letter)
    # my_path = 'C:/Users/Hewlett Packard/Desktop/do/output7.pdf'

    # c = canvas.Canvas(my_path, pagesize=letter)
    c = my_temp(c, client, site, do_date, do_number, po_number,proj_no, client_address_line_1, client_address_line_2, client_address_line_3, client_address_line_4, site_address_line_1, site_address_line_2, site_address_line_3, site_address_line_4, items_list)
    c.setFillColorRGB(0, 0, 1)
    c.setFont("Helvetica", 16)
    # c.drawString(2 * inch, 4 * inch, 'List of items')
    c.showPage()
    c.save()


    # Fetch items after adding to display in the template
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute("SELECT * FROM do_items")
    items = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.form.get('project_id1', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
    created_do = cursor.fetchall()
    cursor = db.execute("SELECT MAX(id) FROM created_do")
    last_enquiry_number = cursor.fetchone()[0]
    sequential_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1
    formatted_sequential_number = f"{sequential_number:04}"
    current_year = datetime.now().strftime("%y")
    do_number_variable = f"DO-{current_year}-{formatted_sequential_number}"
    # print(do_number_variable)
    db.commit()

    return render_template('admin_templates/projects/project_do.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                        user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do,do_number_variable=do_number_variable)

def my_temp(c, client, site, do_date, do_number, po_number,proj_no, client_address_line_1, client_address_line_2, client_address_line_3, client_address_line_4,
            site_address_line_1, site_address_line_2, site_address_line_3, site_address_line_4, items_list):

    c.translate(inch, inch)
    # Define a large font
    c.setFont("Helvetica", 10)
    # Centroid logo resized image
    image_path = 'templates/admin_templates/projects/ces.jpeg'
    image_width = 2  # Set the desired width in inches
    image_height = 0.3  # Set the desired height in inches
    c.drawImage(image_path, 4.8 * inch, 9.3 * inch, width=image_width * inch, height=image_height * inch)
    # Centroid Address
    c.drawString(0.1 * inch, 9.5 * inch, "Centroid Engineering Solutions Pte Ltd")
    c.drawString(0.1 * inch, 9.3 * inch, "Co  Regn No: 201308058R")
    c.drawString(0.1 * inch, 9.1 * inch, "GST Regn No: 201308058R")
    c.drawString(0.1 * inch, 8.9 * inch, "11, Woodlands Close, #07-10")
    c.drawString(0.1 * inch, 8.7 * inch, "Singapore - 737853")

    # Delivery order
    c.setFont("Helvetica-Bold", 15)
    c.drawString(2.7 * inch, 8.7 * inch, 'DELIVERY ORDER')

    # First line from top
    c.setFillColorRGB(0, 0, 0)  # Font color
    c.line(0, 8.6 * inch, 6.8 * inch, 8.6 * inch)
    # Second line
    c.line(0, 7.5 * inch, 6.8 * inch, 7.5 * inch)
    # Third line
    c.line(0, 6.6 * inch, 6.8 * inch, 6.6 * inch)
    # Fourth line
    c.line(0, 6.3 * inch, 6.8 * inch, 6.3 * inch)
    #Top line
    c.line(0, 9.7 * inch, 6.8 * inch, 9.7 * inch)

    # Vertical Lines
    c.line(0.0 * inch, 9.7 * inch, 0.0 * inch, -0.7 * inch)
    c.line(0.5 * inch, 6.6 * inch, 0.5 * inch, 0.4 * inch)
    c.line(5.6 * inch, 6.6 * inch, 5.6 * inch, 0.4 * inch)
    c.line(6.2 * inch, 6.6 * inch, 6.2 * inch, 0.4 * inch)
    c.line(6.8 * inch, 9.7 * inch, 6.8 * inch, -0.7 * inch)

    # Client
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 8.4 * inch, 'Client')
    c.drawString(0.7 * inch, 8.4 * inch, client_address_line_1)

    # Client Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 8.2 * inch, client_address_line_2)
    c.drawString(0.7 * inch, 8.0 * inch, client_address_line_3)
    c.drawString(0.7 * inch, 7.8 * inch, client_address_line_4)

    # Attn
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 7.6 * inch, 'Attn')
    c.drawString(0.7 * inch, 7.6 * inch, 'Mr. George Kyaw')

    # DO NO, Date, Po, Quote Ref, Page
    c.setFont("Helvetica-Bold", 10)
    c.drawString(4.8 * inch, 8.4 * inch, 'DO No')
    c.drawString(4.8 * inch, 8.2 * inch, 'DO Date')
    c.drawString(4.8 * inch, 8.0 * inch, 'PO NO')
    c.drawString(4.8 * inch, 7.8 * inch, 'Proj No')
    c.drawString(4.8 * inch, 7.6 * inch, 'Page')

    # Values
    c.setFont("Helvetica", 10)
    c.drawString(5.6 * inch, 8.4 * inch, do_number)
    c.drawString(5.6 * inch, 8.2 * inch, do_date)
    c.drawString(5.6 * inch, 8.0 * inch, po_number)
    c.drawString(5.6 * inch, 7.8 * inch, proj_no)
    c.drawString(5.6 * inch, 7.6 * inch, '1 of 1')

    # Delivery
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 7.3 * inch, 'Delivery')
    c.drawString(0.7 * inch, 7.3 * inch, site_address_line_1)

    # Delivery Address
    c.setFont("Helvetica", 10)
    c.drawString(0.7 * inch, 7.1 * inch, site_address_line_2)
    c.drawString(0.7 * inch, 6.9 * inch, site_address_line_3)
    c.drawString(0.7 * inch, 6.7 * inch, site_address_line_4)

    # Item table heading
    c.setFont("Helvetica-Bold", 10)
    c.drawString(0.1 * inch, 6.4 * inch, 'S.No')
    c.drawString(2.7 * inch, 6.4 * inch, 'Item Description')
    c.drawString(5.75 * inch, 6.4 * inch, 'Qty')
    c.drawString(6.35 * inch, 6.4 * inch, 'UOM')

    # c.drawString(0.2 * inch, 6.1 * inch, "1")

    c.setFont("Helvetica", 10)

    # Display each item in the list
    row_height = 0.3  # Adjust this value based on your requirement
    start_height = 6.1  # Adjust this value based on your requirement
    displayed_items = set()

    for index, item in enumerate(items_list, start=1):
        current_height = start_height
        # Check if the item has sub-items
        if 'sub_item' in item and item['sub_item']:
            # Display sub-item instead of item and skip serial number
            item_description = item['sub_item']
            item_number = ""
            # Add the sub-item to the set of displayed items
            displayed_items.add(item_description)
        else:
            # Display item and show serial number only if not already displayed
            item_description = item['item']
            if item_description not in displayed_items:
                item_number = str(index)
                # Add the main item to the set of displayed items
                displayed_items.add(item_description)
            else:
                item_number = ""

        c.drawString(0.2 * inch, current_height * inch, item_number)
        c.drawString(0.8 * inch, current_height * inch, item_description)
        c.drawString(5.85 * inch, current_height * inch, str(item['uom']))
        c.drawString(6.5 * inch, current_height * inch, str(item['quantity']))
        start_height = start_height - 0.3

    # Signature
    c.drawString(0.8 * inch, -0.6 * inch, 'Received By')
    c.drawString(4 * inch, -0.6 * inch, 'for Centroid Engineering Solutions')

    c.line(0,  0.4 * inch, 6.8 * inch, 0.4 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)

    return c

@app.route('/generate_do', methods=['GET', 'POST'])
@login_required
def generate_do():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    user = get_current_user()
    db = get_database()

    if request.method == 'POST':
        do_number = str( request.form.get('do_number'))
        do_date = request.form.get('do_date')
        proj_no = request.form.get('proj_no')
        project_name = request.form.get('name')
        email = request.form.get('email')
        po_number = request.form.get('po_number')
        client = request.form.get('client')
        site = request.form.get('site')
        client_address = request.form.get('client_address')
        site_address = request.form.get('site_address')

        client_address_line_1  = request.form.get('client_address_line_1')
        client_address_line_2  = request.form.get('client_address_line_2')
        client_address_line_3  = request.form.get('client_address_line_3')
        client_address_line_4  = request.form.get('client_address_line_4')

        site_address_line_1  = request.form.get('site_address_line_1')
        site_address_line_2  = request.form.get('site_address_line_2')
        site_address_line_3  = request.form.get('site_address_line_3')
        site_address_line_4  = request.form.get('site_address_line_4')



        cursor = db.cursor()
        # do_number = 'DO123'
        cursor.execute("SELECT * FROM do_items WHERE do_number = ?", (do_number,))
        items_data = cursor.fetchall()

        # Store data in a dictionary
        items_dict_list = []
        for item in items_data:
            item_dict = {'sub_item':item['sub_item'],'item': item['item'],'uom': item['uom'], 'quantity': item['quantity'] }
            items_dict_list.append(item_dict)

        generate_delivery_order_pdf(do_number, do_date, proj_no, project_name, email, po_number, client, site, client_address_line_1, client_address_line_2, client_address_line_3, client_address_line_4,
                                     site_address_line_1, site_address_line_2, site_address_line_3, site_address_line_4,items_dict_list)






    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor.execute("SELECT * FROM do_items")
    items = cursor.fetchall()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    project_id = request.form.get('project_id1', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor = db.execute("SELECT * FROM enquiries WHERE EnquiryNumber = ?", (project_id,))
    enquiries_details = cursor.fetchone()
    from datetime import datetime
    current_date = datetime.now()
    formatted_date = current_date.strftime("%d %m %y")
    cursor = db.execute('SELECT * FROM created_do ORDER BY id DESC')
    created_do = cursor.fetchall()
    cursor = db.execute("SELECT MAX(id) FROM created_do")
    cursor.execute("SELECT SUBSTR(do_number, -4) as last_digits FROM created_do WHERE id = (SELECT MAX(id) FROM created_do)")
    result = cursor.fetchone()

    # Extract the value from the 'last_digits' column
    last_enquiry_number = int(result['last_digits']) if result else 0

    # last_enquiry_number = cursor.fetchone()[0]
    sequential_number = last_enquiry_number + 1 if last_enquiry_number is not None else 1

    formatted_sequential_number = f"{sequential_number:04}"
    current_year = datetime.now().strftime("%y")
    do_number_variable = f"D-{current_year}-{formatted_sequential_number}"


    cursor.execute("INSERT INTO created_do (do_number, do_date, proj_no, pro_name, client, site, po_number, status, created_by, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (do_number, do_date, proj_no, project_name, client, site, po_number, 'Open', user['name'], email))

    db.commit()

    return render_template('admin_templates/projects/project_do.html', current_date=formatted_date, enquiries_details=enquiries_details, is_pm=is_pm, department_code=department_code, items=items,
                        user=user, project_id=project_id, project_details=project_details,form_data=dict(),created_do=created_do,do_number_variable=do_number_variable)

from calendar import monthrange
import calendar
@app.route('/admin_employee_view_data/', methods=['GET', 'POST'])
@login_required
def admin_employee_view_data():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    department_code = get_department_code_by_username( user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()
    from datetime import datetime, timedelta
    project_id1 = None


    current_year = datetime.now().year
    department_code = get_department_code_by_username(user['name'])
    cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (department_code,))
    usernames = sorted([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]
    data = []
    last_day = None
    start_day = None
    employee_id = request.args.get('selected_employee')
    month_options = [
        {"value": "01", "label": "January"},
        {"value": "02", "label": "February"},
        {"value": "03", "label": "March"},
        {"value": "04", "label": "April"},
        {"value": "05", "label": "May"},
        {"value": "06", "label": "June"},
        {"value": "07", "label": "July"},
        {"value": "08", "label": "August"},
        {"value": "09", "label": "September"},
        {"value": "10", "label": "October"},
        {"value": "11", "label": "November"},
        {"value": "12", "label": "December"}
    ]

    if request.method == 'POST':
        # Assuming the date format is 'DD MM YYYY'
        from datetime import datetime

        # Get current date
        current_date = datetime.now()
        temp_end_date_str = current_date.strftime('%Y-%m-%d')
        temp = current_date - timedelta(days=30)
        temp_start_date_str = temp.strftime('%Y-%m-%d')
        current_date = datetime.now()
        start_date_str = request.form.get('start_date') if request.form.get('start_date') else None
        end_date_str = request.form.get('end_date') if request.form.get('end_date') else None
        project_id1 = request.form.get('project_id') if request.form.get('project_id') else None
        employee_id = request.form.get('employee_id')

        if not start_date_str:
           temp = 1
           start_date_str = temp_start_date_str

        if not end_date_str:
            temp = 1
            end_date_str = temp_end_date_str


        date_total_hours = {}
        project_hours = {}
        current_year = datetime.now().year
        current_month = datetime.now().month
        workingDate = f"{current_month} {current_year}"
        nyear = int(current_year)
        nmonth = int(current_month)
        month_name = calendar.month_name[nmonth]

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        date_range = generate_date_range(start_date, end_date)
        leave_dates_dict = {}


        if not employee_id:
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            cursor.execute('SELECT DISTINCT username FROM admin_user WHERE department_code >= ?', (department_code,))
            employee_ids = sorted([row[0] for row in cursor.fetchall()])

            for employeeID in employee_ids:
                # print("...................loop is on tis man.................",employeeID)
                start_date_str = request.form.get('start_date')
                end_date_str = request.form.get('end_date')

                if not project_id1:
                    cursor.execute('SELECT employeeID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND formatted_date BETWEEN ? AND ?', (employeeID, start_date_str, end_date_str))
                else:
                    if temp == 1:
                        cursor.execute('SELECT employeeID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND projectID = ?', (employeeID, project_id1))
                    else:
                        cursor.execute('SELECT employeeID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND formatted_date BETWEEN ? AND ?  AND projectID = ?', (employeeID, start_date_str, end_date_str, project_id1))

                raw_data = cursor.fetchall()


                if employeeID not in project_hours:
                    # print("missed on added here..........")
                    project_hours[employeeID] = {'total_hours': 0, 'date_hours': {}, 'departmentID': None}  # Adjust departmentID as per your needs



                for entry in raw_data:

                    project_id = entry['employeeID']
                    working_date = entry['workingDate']
                    hours_worked = entry['hoursWorked']
                    department_id = entry['departmentID']  # Add departmentID

                    if project_id not in project_hours:
                        # print("................project_id..........is being added............",project_id)
                        project_hours[project_id] = {'total_hours': 0, 'date_hours': {}, 'departmentID': department_id}

                    if working_date not in project_hours[project_id]['date_hours']:
                        project_hours[project_id]['date_hours'][working_date] = hours_worked
                    else:
                        project_hours[project_id]['date_hours'][working_date] += hours_worked

                    project_hours[project_id]['total_hours'] += hours_worked

                # print("............project_hours..........\n\n\n\n",project_hours)


                data = [{'projectID': project_id, 'departmentID': project_data['departmentID'], 'date_hours': project_data['date_hours'], 'total_hours': project_data['total_hours']} for project_id, project_data in project_hours.items()]
                # data = [{'projectID': project_id, 'departmentID': project_data['departmentID'], 'date_hours': project_data['date_hours'], 'total_hours': project_data['total_hours'], 'leave': ''} for project_id, project_data in project_hours.items()]


                cursor.execute('SELECT employeeID, section_code, leave_type, leave_date, department_code FROM leaves WHERE employeeID = ?', (employeeID,))
                raw_data = cursor.fetchall()

                import datetime

                leave_dates = []
                for row in raw_data:
                    leave_date = datetime.datetime.strptime(row[3], '%Y-%m-%d').strftime('%d %m %Y')
                    leave_dates.append(leave_date)

                leave_dates_dict[employeeID] = leave_dates
                # print("..\n\n\n\n\n\n\n\n........leave_dates_dict...........",leave_dates_dict)


            for project in data:
                date_hours = project['date_hours']
                for date, hours_worked in date_hours.items():
                    date_total_hours[date] = date_total_hours.get(date, 0) + hours_worked

            total_hours_sum = sum(date_total_hours.values())

            #trash
            department_plot_data = "ravi"
            plot_data ="rafmaslf"

            # Iterate through the data list
            for entry in data:
                # Get the projectID for the current entry
                project_id = entry['projectID']

                # Check if the projectID exists in the leave_dates_dict
                if project_id in leave_dates_dict:
                    # If it exists, update the 'leave' key with the leave dates
                    entry['leaves'] = leave_dates_dict[project_id]
                else:
                    # If it doesn't exist, set an empty list for 'leaves'
                    entry['leaves'] = []

            # Print the updated data
            # print("Updated data:")
            # print(data)


            return render_template("admin_templates/projects/admin_employee_view_data.html",department_code=department_code,department_plot_data=department_plot_data,graph = plot_data,is_pm=is_pm,
                               total_hours_sum=total_hours_sum, user=user, date_total_hours = date_total_hours,usernames=usernames, current_year=nyear, data=data, employee_id=employee_id,
                                project_id1=project_id1,project_ids=project_ids, selected_month=month_name, last_day=last_day, month=nmonth, start_day=start_day, month_options=month_options
                                ,start_date=start_date,end_date=end_date,date_range=date_range)


        # print("employee seected........................................",employee_id)

        month = 8
        year = 2024
        workingDate = f"{month} {year}"
        nyear = int(current_year)
        nmonth = int(current_month)
        month_name = calendar.month_name[nmonth]
        start_date = datetime(nyear, nmonth, 1)
        start_day = start_date.weekday()
        last_day = monthrange(nyear, nmonth)[1] if nyear and nmonth else None
        project_hours = {}

        if project_id1 and start_date_str and end_date_str: #project is elected
            # print("........project_id1 and start_date_str and end_date_str.......................")
            cursor.execute('SELECT projectID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND formatted_date BETWEEN ? AND ? AND section_code = ? AND projectID = ?', (employee_id, start_date_str, end_date_str, 4000, project_id1))

        elif not project_id1 and start_date_str and end_date_str: #project is not elected
            # print("..................start_date_str........................",start_date_str,".............end_date_str......................",end_date_str)
            # print("................not project_id1 and start_date_str and end_date_str:....................")
            cursor.execute('SELECT projectID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND formatted_date BETWEEN ? AND ? AND section_code = ?', (employee_id, start_date_str, end_date_str, 4000))

        if project_id1 and (not start_date_str or not end_date_str):
            # print("..............project_id1 and (not start_date_str or not end_date_str)........................")
            cursor.execute('SELECT projectID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ?  AND section_code = ? AND projectID = ?', (employee_id, 4000,project_id1))

        if not project_id1 and not start_date_str and not end_date_str:
            # print(".....................not project_id1 and not start_date_str and not end_date_str........................")
            cursor.execute('SELECT projectID, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ?  AND section_code = ?', (employee_id, 4000))

        raw_data = cursor.fetchall()
        # print("...........raw_data.............\n",raw_data)

        cursor.execute('SELECT section_code, workingDate, hoursWorked, departmentID FROM workingHours WHERE employeeID = ? AND formatted_date BETWEEN ? AND ?', (employee_id, start_date_str,end_date_str))
        raw_data1 = cursor.fetchall()
        # print(".............raw_data1.................\n",raw_data1)


        project_hours = {}

        for entry in raw_data:
            project_id = entry['projectID']
            working_date = entry['workingDate']
            hours_worked = entry['hoursWorked']
            department_id = entry['departmentID']  # Add departmentID

            if project_id not in project_hours:
                project_hours[project_id] = {'total_hours': 0, 'date_hours': {}, 'departmentID': department_id}

            if working_date not in project_hours[project_id]['date_hours']:
                project_hours[project_id]['date_hours'][working_date] = hours_worked
            else:
                project_hours[project_id]['date_hours'][working_date] += hours_worked

            project_hours[project_id]['total_hours'] += hours_worked

        for entry in raw_data1:
            project_id = entry['section_code']
            if project_id == 4000:
                continue
            working_date = entry['workingDate']
            hours_worked = entry['hoursWorked']
            department_id = entry['departmentID']  # Add departmentID

            if project_id not in project_hours:
                project_hours[project_id] = {'total_hours': 0, 'date_hours': {}, 'departmentID': department_id}

            if working_date not in project_hours[project_id]['date_hours']:
                project_hours[project_id]['date_hours'][working_date] = hours_worked
            else:
                project_hours[project_id]['date_hours'][working_date] += hours_worked

            project_hours[project_id]['total_hours'] += hours_worked

        data = [{'projectID': project_id, 'departmentID': project_data['departmentID'], 'date_hours': project_data['date_hours'], 'total_hours': project_data['total_hours']} for project_id, project_data in project_hours.items()]
        # data = [{'projectID': project_id, 'departmentID': project_data['departmentID'], 'date_hours': project_data['date_hours'], 'total_hours': project_data['total_hours'], 'leave': ''} for project_id, project_data in project_hours.items()]

        # print(data)
        # print(data)
        date_total_hours = {}
        for project in data:
            date_hours = project['date_hours']
            for date, hours_worked in date_hours.items():
                date_total_hours[date] = date_total_hours.get(date, 0) + hours_worked


        # print("date_total_hours23432..........",date_total_hours)
        total_hours_sum = sum(date_total_hours.values())


        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').strftime('%d %m %Y')
        date_range = generate_date_range(start_date, end_date)
        import datetime

        cursor.execute('SELECT employeeID, section_code, leave_type, leave_date, department_code, leave_duration FROM leaves WHERE employeeID = ?', (employee_id,))
        raw_data = cursor.fetchall()
        leave_dates = []
        for row in raw_data:
            leave_date = datetime.datetime.strptime(row[3], '%Y-%m-%d').strftime('%d %m %Y')
            leave_dates.append((leave_date, row[5]))  # Storing leave date and duration together


        if not data:
            data = [{'projectID': None, 'departmentID': None, 'date_hours': {}, 'total_hours': 0, 'leaves': leave_dates}]
        else:
            for entry in data:
                entry['leaves'] = leave_dates


        # print(".data..............",data)
        return render_template("admin_templates/projects/admin_employee_view_data.html",department_code=department_code,is_pm=is_pm,total_hours_sum=total_hours_sum, user=user, date_total_hours = date_total_hours,
                               usernames=usernames, current_year=nyear, data=data, employee_id=employee_id, project_id1=project_id1,project_ids=project_ids, selected_month=month_name, last_day=last_day,
                              leave_dates=leave_dates, month=nmonth, start_day=start_day, month_options=month_options,start_date=start_date,end_date=end_date,date_range=date_range)

    employee_id = request.args.get('selected_employee')
    current_year = datetime.now().year
    current_month = datetime.now().month
    workingDate = f"{current_month} {current_year}"
    nyear = int(current_year)
    nmonth = int(current_month)
    month_name = calendar.month_name[nmonth]
    start_date = datetime(nyear, nmonth, 1)
    start_day = start_date.weekday()
    last_day = monthrange(nyear, nmonth)[1] if nyear and nmonth else None
    project_hours = {}
    cursor.execute('SELECT projectID, workingDate, hoursWorked FROM workingHours WHERE employeeID = ? AND substr(workingDate, 4) = ?', (employee_id, workingDate,))
    raw_data = cursor.fetchall()
    cursor.execute('SELECT section_code, workingDate, hoursWorked FROM workingHours WHERE employeeID = ? AND substr(workingDate, 4) = ?', (employee_id, workingDate,))
    raw_data1 = cursor.fetchall()

    for entry in raw_data:
        project_id = entry['projectID']
        working_date = entry['workingDate'][:2]
        hours_worked = entry['hoursWorked']
        if project_id not in project_hours:
            project_hours[project_id] = {'total_hours': 0, 'date_hours': {}}

        if working_date not in project_hours[project_id]['date_hours']:
            project_hours[project_id]['date_hours'][working_date] = hours_worked
        else:
            project_hours[project_id]['date_hours'][working_date] += hours_worked

        project_hours[project_id]['total_hours'] += hours_worked

    for entry in raw_data1:
        project_id = entry['section_code']
        if project_id == 4000:
            continue
        working_date = entry['workingDate'][:2]
        hours_worked = entry['hoursWorked']

        if project_id not in project_hours:
            project_hours[project_id] = {'total_hours': 0, 'date_hours': {}}

        if working_date not in project_hours[project_id]['date_hours']:
            project_hours[project_id]['date_hours'][working_date] = hours_worked
        else:
            project_hours[project_id]['date_hours'][working_date] += hours_worked

        project_hours[project_id]['total_hours'] += hours_worked

    data = [{'projectID': project_id, 'date_hours': project_data['date_hours'], 'total_hours': project_data['total_hours']} for project_id, project_data in project_hours.items()]
    date_total_hours = {}

    for project in data:
        date_hours = project['date_hours']

        for date, hours_worked in date_hours.items():
            date_total_hours[date] = date_total_hours.get(date, 0) + hours_worked

    total_hours_sum = sum(date_total_hours.values())

    plotting_data = copy.deepcopy(data)  # Perform a deep copy of the original data for plotting

    for d in plotting_data:
        if d['projectID'] not in [5000, 5001, 5002, 5003]:
            d['projectID'] = 400
    # Grouping all data under projectID 4000
    grouped_data = {}
    for d in plotting_data:
        if d['projectID'] not in grouped_data:
            grouped_data[d['projectID']] = {'total_hours': 0, 'date_hours': {}}
        for date, hours in d['date_hours'].items():
            if date in grouped_data[d['projectID']]['date_hours']:
                grouped_data[d['projectID']]['date_hours'][date] += hours
            else:
                grouped_data[d['projectID']]['date_hours'][date] = hours
        grouped_data[d['projectID']]['total_hours'] += d['total_hours']
    # Creating the pie chart with grouped data
    grouped_labels = [projectID for projectID in grouped_data.keys()]
    grouped_total_hours = [grouped_data[projectID]['total_hours'] for projectID in grouped_data]
    # Creating the pie chart
    plt.figure(figsize=(4, 4), facecolor='none')  # Set the facecolor to 'none' for a transparent background
    plt.subplots_adjust(0, 0, 1, 1)  # Set margins to zero on all four sides
    plt.pie(grouped_total_hours, labels=grouped_labels, autopct='%1.1f%%', startangle=140)
    plt.gca().set_facecolor('none')  # Set the current axis background color to 'none' for transparency

    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png', transparent=True)  # Save the image with a transparent background
    image_stream.seek(0)
    plot_data = base64.b64encode(image_stream.getvalue()).decode()

    plt.clf()
    plt.close()
    department_plot_data = None


    # print("............data...................\n",data)

    return render_template("admin_templates/projects/admin_employee_view_data.html",department_code=department_code,department_plot_data = department_plot_data,graph = plot_data,total_hours_sum=total_hours_sum,
                           user=user,date_total_hours = date_total_hours, usernames=usernames, current_year=nyear, data=data, employee_id=employee_id, selected_month=month_name, last_day=last_day, month=nmonth,
                            project_id1=project_id1 ,project_ids=project_ids, start_day=start_day, month_options=month_options,is_pm = is_pm)

@app.route('/admin_temp_employee', methods=['GET', 'POST'])
@login_required
def admin_temp_employee():
    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    is_pm = is_pm_for_project(user['name'])
    cursor.execute('SELECT username FROM admin_user')
    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    if user['name'] not in usernames:
        usernames.append(user['name'])
    show = 1
    show2 = 1

    if 'confirm' in request.form:
        data = request.form.getlist('data[]')
        # print(data)
        leavedata = request.form.getlist('leavedata[]')

        selected_projects = request.form.getlist('selected_projects[]')  # Get selected checkboxes
        # print("..................selected_projects..........",selected_projects)
        selected_leave_ids = request.form.getlist('selected_leave_ids[]')
        # print("....................selected_projects.....................", selected_projects)
        if data:
            flash_message_shown = False  # Initialize the flag
            for item in data:
                entryID,projectID, client, project_name, workingDate, hoursWorked, employeeID, departmentID,section_code = item.split('|')
                original_date = datetime.strptime(workingDate, '%d %m %Y')
                formatted_date = original_date.strftime('%Y-%m-%d')

                if entryID in selected_projects:  # Check if this row is selected
                    # print("...............projectID..................",entryID)
                    existing_row = db.execute( "SELECT hoursWorked FROM workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?",
                        (projectID, departmentID, employeeID, workingDate,section_code)).fetchone()

                    if existing_row:
                        existing_hours = existing_row[0]
                        new_hours = float(existing_hours) + float(hoursWorked)
                        db.execute( "UPDATE workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?",
                            (new_hours, projectID, departmentID, employeeID, workingDate,section_code))

                    else:
                        db.execute("INSERT INTO workingHours (projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, client,section_code,formatted_date) VALUES (?,?,?, ?, ?, ?, ?, ?, ?)",
                            (projectID, departmentID, employeeID, workingDate, hoursWorked, project_name, client,section_code,formatted_date))
                    # flash('Your working hours have been recorded successfully.', 'timesheet')
                    db.execute("DELETE FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ?",(projectID, departmentID, employeeID, workingDate))
                    if not flash_message_shown:
                        flash('Your working hours have been recorded successfully.', 'timesheet')
                        flash_message_shown = True  # Set the flag to True after flashing the message


                show2 = 3

        from dateutil import parser
        public_holidays = set()
        cursor.execute('SELECT date FROM public_holidays')
        public_holidays_data = cursor.fetchall()
        for holiday in public_holidays_data:
            public_holidays.add(parser.parse(holiday['date']).date())

        for item in leavedata:
            id,start_date,end_date,number_of_days,leave_type,employeeID,section_code  = item.split('|')
            department_code = get_department_code_by_username(employeeID)
            days = number_of_days
            print(".................department_code............",id,start_date,end_date,number_of_days,leave_type,employeeID,section_code)
            if 'Days' in number_of_days:
                number_of_days = 'L'
            elif 'Half Day' in number_of_days:
                number_of_days = number_of_days.replace('Half Day', 'HF')
            elif 'Hours' in number_of_days:
                number_of_days = number_of_days.replace('Hours', 'Hr')

            print(".................number_of_days............",number_of_days)

            from dateutil import parser
            start = datetime.strptime(start_date, "%d %m %Y")
            formatted_start = start.strftime("%Y-%m-%d")
            end = datetime.strptime(end_date, "%d %m %Y")
            formatted_end = end.strftime("%Y-%m-%d")
            start_date1 = parser.parse(formatted_start)
            end_date1 = parser.parse(formatted_end)
            if f"{id}" in selected_leave_ids:
                # current_date = start_date1
                # while current_date <= end_date1:
                #     if current_date.weekday() not in (5, 6) and current_date.date() not in public_holidays:  # Exclude Saturdays (5) and Sundays (6)
                #         db.execute('INSERT INTO leaves (employeeID, section_code, leave_type, leave_date,leave_duration) VALUES (?, ?, ?, ?, ?)',
                #             (employeeID, section_code, leave_type, current_date.strftime('%Y-%m-%d'),number_of_days))
                #     current_date += timedelta(days=1)

                db.execute( 'INSERT INTO leaves_yet_to_approve (employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (employeeID, section_code, leave_type,formatted_start, formatted_end, days, department_code, 'Pending'))

                flash('Your leave has been recorded successfully. Please wait for approval.', 'leavestatus')
                db.execute("DELETE FROM temp_leave WHERE id = ?",(id,))

            show = 7

    elif 'delete' in request.form:

        data = request.form.getlist('data[]')
        selected_projects = request.form.getlist('selected_projects[]')  # Get selected checkboxes
        leavedata = request.form.getlist('leavedata[]')
        selected_leave_ids = request.form.getlist('selected_leave_ids[]')
        for item in data:
            entryID,projectID, client, project_name, workingDate, hoursWorked, employeeID, departmentID,section_code = item.split('|')
            if entryID in selected_projects:  # Check if this row is selected
                db.execute("DELETE FROM temp_workingHours WHERE entryID = ?",(entryID,))
                flash('Working Hours deleted successfully.', 'timesheet')
            show2 = 3

        for item in leavedata:
            id, employeeID, section_code, leave_type,  start_date, end_date,  number_of_days = item.split('|')

            if f"{id}" in selected_leave_ids:  # Check if this row is selected
                db.execute("DELETE FROM temp_leave WHERE id = ? ",(id,))
            show = 7

        db.commit()

    user = get_current_user()
    username = user['name']
    depart = get_department_code_by_username(user['name'])
    if depart == 1000:
        pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
    else:
        pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))
    leavepro = db.execute('SELECT id, employeeID, section_code, leave_type,  start_date, end_date,  number_of_days, department_code FROM temp_leave')
    allpro = []
    temp_leave = []
    for pro_row in pro_cur.fetchall():
        pro_dict = dict(pro_row)
        allpro.append(pro_dict)

    for leavepro in leavepro.fetchall():
        pro_dict = dict(leavepro)
        temp_leave.append(pro_dict)

    current_date = datetime.now().date()
    date_range = [current_date - timedelta(days=i) for i in range(15)]
    # Query the database for the total hours worked on each date
    workingHours_allpro = []
    for date in date_range:
        formatted_date = date.strftime('%d-%m-%y')
        total_hours = 0
        # Query the database for the total hours worked on the current date
        rows = db.execute('''SELECT SUM(hoursWorked) as totalHours FROM workingHours WHERE employeeID = ? AND workingDate = ?''', (user['name'], formatted_date)).fetchone()
        if rows and rows['totalHours'] is not None:
            total_hours = rows['totalHours']
        workingHours_allpro.append({'workingDate': formatted_date, 'totalHours': total_hours})

    workingHours_allpro = workingHours_allpro[::-1]
    workingHours_allpro.reverse()
    username = user['name']
    department_code = get_department_code_by_username(username)
    pm_status = get_pm_status(username)
    client_suggestions = get_client_names()
    tempclientname = request.form.get('temp_client_name')
    project_id_suggestions = get_project_ids_by_client(tempclientname)
    project_names_suggestions = get_project_names()
    current_date = datetime.now().date()
    min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')

    return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date, pm_status=pm_status, department_code=department_code,
                        client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,usernames=usernames,is_pm = is_pm,temp_leave=temp_leave,
                        project_names_suggestions=project_names_suggestions, allpro=allpro,show = show, show2 = show2,
                        workingHours_allpro=workingHours_allpro)  # Pass total_hours here

from datetime import datetime, timedelta

def check_leave_overlap(employee_id, startdate, enddate):
    db = get_database()
    cursor = db.cursor()
    startdate = datetime.strptime(startdate, "%d %m %Y")
    enddate = datetime.strptime(enddate, "%d %m %Y")
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
    print("............conflicting_leave.........",conflicting_leave)

    if conflicting_leave:
        # Print the values in the conflicting_leave row
        print(f"ID: {conflicting_leave[0]}")
        print(f"Employee ID: {conflicting_leave[1]}")
        print(f"Section Code: {conflicting_leave[2]}")
        print(f"Leave Type: {conflicting_leave[3]}")
        print(f"Leave Date: {conflicting_leave[4]}")
        print(f"Leave Duration: {conflicting_leave[5]}")
        print(f"Department Code: {conflicting_leave[6]}")
        print(f"Status: {conflicting_leave[7]}")
        print(f"Approved By: {conflicting_leave[8]}")
        print(f"Approved Date: {conflicting_leave[9]}")
        print(f"Temp ID: {conflicting_leave[10]}")

    return conflicting_leave

from datetime import datetime
@app.route('/admin_employee', methods=['GET', 'POST'])
@login_required
def admin_employee():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    is_pm = is_pm_for_project(user['name'])
    is_pe = is_pe_for_project(user['name'])
    depart = get_department_code_by_username(user['name'])
    db = get_database()
    cursor = db.cursor()


    if depart == 1002:
        cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
    elif depart == 1005:
        cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
    elif depart == 1007:
        cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
    else:
        cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

    usernames1 = [row[0] for row in cursor.fetchall()]
    usernames = sorted(usernames1, key=lambda x: x.lower())
    if user['name'] not in usernames:
        usernames.append(user['name'])




    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        current_section = request.form.get('current_section')

        if current_section == 'prj':
            employee_id = request.form['employee_id']
            # print("sairammm..................................",employee_id)
            project_id = request.form['project_id']
            client = request.form['client']
            project_name = request.form['project_name']
            date1 = request.form.get('date')
            date = convert_date_format(date1)
            hours_worked = request.form['hours_worked']
            department_code = request.form['department_code']
            section_code = request.form['section']
            project_info = db.execute('SELECT pm, pe FROM projects WHERE id = ?', (project_id,)).fetchone()
            if project_info:
                pm, pe = project_info

            existing_row = db.execute(
                'SELECT hoursWorked FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                (project_id, department_code, employee_id, date,section_code)).fetchone()

            project_status = check_project_status(project_id)
            if project_status == 'Closed':
                flash('Project is closed. Please Contact Administrator.....!', 'admin_employee1')
            if project_status == 'Select':
                flash('Project is not opened yet!', 'admin_employee')

            if employee_id != user['name']:
                if depart != 1000 and user['name'] != pm and user['name'] != pe:
                    flash("You don't have permission to allocate hours. Please contact the administrator.", 'admin_employee')

            if project_status != 'Closed':
                print(".......................project_status........",project_status)

                if existing_row:
                    print(".......inside existing row..................")

                    existing_hours = float(existing_row[0])
                    new_hours = existing_hours + float(hours_worked)
                    if new_hours > 24:
                        flash(' working cannot exceed 24 hours.', 'admin_employee')
                    else:
                        db.execute('UPDATE temp_workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                            (new_hours, project_id, department_code, employee_id, date,section_code))
                else:
                    print(".......else condition................")
                    if float(hours_worked) > 24:
                        flash('Hours worked cannot exceed 24 hours.', 'admin_employee')
                    else:
                        db.execute('INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked,section_code,user) VALUES (?,?,?, ?, ?, ?, ?, ?, ?)',
                            (project_id, department_code, employee_id, project_name, client, date, hours_worked,section_code,user['name']))

            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))


            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)


            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')
            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enuiry_ids = get_enuiry_ids()
            # print(".........enquiry_client_suggestions",enquiry_client_suggestions)

            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames1 = [row[0] for row in cursor.fetchall()]
            usernames = sorted(usernames1, key=lambda x: x.lower())
            if user['name'] not in usernames:
                usernames.append(user['name'])

            allpro
            db.commit()
            show2 = 3
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                                is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave,show2=show2)

        elif current_section == 'est':
            employee_id = request.form['employee_id']
            est_project_id = request.form['enquiry_ids']
            est_client = request.form['est_client']
            est_project_name = request.form['est_project_name']
            est_date1 = request.form.get('est_date')
            est_date = convert_date_format(est_date1)
            est_hours_worked = request.form['est_hours_worked']
            est_department_code = request.form['est_department_code']
            est_section_code = request.form['est_section']
            existing_row = db.execute(
                'SELECT hoursWorked FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                (est_project_id, est_department_code, employee_id, est_date,est_section_code)).fetchone()
            project_status = check_project_status(est_project_id)
            if project_status == 'Closed':
                flash('Project is closed. Please Contact Administrator.....!', 'admin_employee')
            if project_status == 'Select':
                flash('Project is not opened yet, Please Contact Administrator.....!', 'admin_employee')
            elif existing_row:
                existing_hours = float(existing_row[0])
                new_hours = existing_hours + float(est_hours_worked)
                if new_hours > 24:
                    flash(' working cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('UPDATE temp_workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                        (new_hours, est_project_id, est_department_code, employee_id, est_date,est_section_code))
            else:
                if float(est_hours_worked) > 24:
                    flash('Hours worked cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked,section_code, user) VALUES (?,?,?, ?, ?, ?, ?, ?, ?)',
                        (est_project_id, est_department_code, employee_id, est_project_name, est_client, est_date, est_hours_worked,est_section_code,user['name']))


            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID, projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))


            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)

            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')
            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            enuiry_ids = get_enuiry_ids()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames1 = [row[0] for row in cursor.fetchall()]
            usernames = sorted(usernames1, key=lambda x: x.lower())
            if user['name'] not in usernames:
                usernames.append(user['name'])

            db.commit()
            show2 = 3
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                                is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave, show2=show2)

        elif current_section == 'oh':
            employee_id = request.form['employee_id']
            oh_date1 = request.form.get('oh_date')
            oh_date = convert_date_format(oh_date1)
            oh_hours_worked = request.form['oh_hours_worked']
            oh_department_code = request.form['oh_department_code']
            project_id = 5001
            oh_section_code = request.form['oh_section']


            if float(oh_hours_worked) > 24:
                flash('Hours worked cannot exceed 24 hours.', 'admin_employee')
            else:
                db.execute('INSERT INTO temp_workingHours (projectID,departmentID, employeeID, workingDate, hoursWorked,section_code,user) VALUES (?,?,? ,?, ?, ?, ?)',
                        (project_id,oh_department_code,employee_id,oh_date,oh_hours_worked,oh_section_code,user['name']))

            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))


            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)


            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')
            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            enuiry_ids = get_enuiry_ids()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames = [row[0] for row in cursor.fetchall()]
            if user['name'] not in usernames:
                usernames.append(user['name'])
            usernames = sorted(usernames)

            db.commit()
            show2=3
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                                is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave,show2=show2)

        elif current_section == 'ser':
            employee_id = request.form['employee_id']
            ser_client = request.form['ser_client']
            project_id = 5002
            ser_project_name = request.form['ser_project_name']
            ser_date1 = request.form.get('ser_date')
            ser_date = convert_date_format(ser_date1)
            ser_hours_worked = request.form['ser_hours_worked']
            ser_department_code = request.form['ser_department_code']
            ser_section_code = request.form['ser_section']
            existing_row = db.execute(
                'SELECT hoursWorked FROM temp_workingHours WHERE project_name = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                (project_id, ser_department_code, employee_id, ser_date,ser_section_code)).fetchone()
            project_status = check_project_status(project_id)
            if project_status == 'Closed':
                flash('Project is closed. Please Contact Administrator.....!', 'admin_employee')
            if project_status == 'Select':
                flash('Project is not opened yet, Please Contact Administrator.....!', 'admin_employee')
            elif existing_row:
                existing_hours = float(existing_row[0])
                new_hours = existing_hours + float(ser_hours_worked)
                if new_hours > 24:
                    flash(' working cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('UPDATE temp_workingHours SET hoursWorked = ? WHERE project_name = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                        (new_hours, ser_project_name, ser_department_code, employee_id, ser_date,ser_section_code))
            else:
                if float(ser_hours_worked) > 24:
                    flash('Hours worked cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked,section_code,user) VALUES (?,?,?, ?, ?, ?, ?, ?, ?)',
                        (project_id, ser_department_code, employee_id, ser_project_name, ser_client, ser_date, ser_hours_worked,ser_section_code,user['name']))

            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID, projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))

            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)

            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')
            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            enuiry_ids = get_enuiry_ids()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames = [row[0] for row in cursor.fetchall()]
            if user['name'] not in usernames:
                usernames.append(user['name'])
            usernames = sorted(usernames)

            db.commit()
            show2=3
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                               is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave,show2=show2)

        elif current_section == 'war':
            employee_id = request.form['employee_id']
            war_project_id = request.form['war_project_id']
            war_client = request.form['war_client']
            war_project_name = request.form['war_project_name']
            war_date1 = request.form.get('war_date')
            war_date = convert_date_format(war_date1)
            war_hours_worked = request.form['war_hours_worked']
            war_department_code = request.form['war_department_code']
            war_section_code = request.form['war_section']
            existing_row = db.execute(
                'SELECT hoursWorked FROM temp_workingHours WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                (war_project_id, war_department_code, employee_id, war_date,war_section_code)).fetchone()
            project_status = check_project_status(war_project_id)
            if project_status == 'Closed':
                flash('Project is closed. Please Contact Administrator.....!', 'admin_employee')
            if project_status == 'Select':
                flash('Project is not opened yet, Please Contact Administrator.....!', 'admin_employee')
            elif existing_row:
                existing_hours = float(existing_row[0])
                new_hours = existing_hours + float(war_hours_worked)
                if new_hours > 24:
                    flash(' working cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('UPDATE temp_workingHours SET hoursWorked = ? WHERE projectID = ? AND departmentID = ? AND employeeID = ? AND workingDate = ? AND section_code=?',
                        (new_hours, war_project_id, war_department_code, employee_id, war_date,war_section_code))
            else:
                if float(war_hours_worked) > 24:
                    flash('Hours worked cannot exceed 24 hours.', 'admin_employee')
                else:
                    db.execute('INSERT INTO temp_workingHours (projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked,section_code,user) VALUES (?,?,?, ?, ?, ?, ?, ?, ?)',
                        (war_project_id, war_department_code, employee_id, war_project_name, war_client, war_date, war_hours_worked,war_section_code,user['name']))

            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))


            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)


            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')

            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            enuiry_ids = get_enuiry_ids()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames = [row[0] for row in cursor.fetchall()]
            if user['name'] not in usernames:
                usernames.append(user['name'])
            usernames = sorted(usernames)

            db.commit()
            show2=3
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                                is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave,show2=show2)

        elif current_section == 'lea':
            # employee_id = user['name']
            employee_id = request.form['employee_id']
            from dateutil import parser

            startdate1 = request.form.get('start_lea_date')
            leave_type = request.form.get('leave_type')
            enddate1 = request.form.get('end_lea_date')
            lea_duration = request.form.get('leave_duration')  # Added to capture leave duration
            lea_section_code = request.form['lea_section']
            enddate = convert_date_format(enddate1)
            startdate = convert_date_format(startdate1)
            department_code = get_department_code_by_username(employee_id)
            # print(".........startdate........enddate.........leave_type....employee_id....",startdate,enddate,leave_type,employee_id)
            temp_check_leave_overlap = check_leave_overlap(employee_id,startdate,enddate)
            if not temp_check_leave_overlap:

                if lea_duration == 'half_day':
                    leave_time = request.form.get('leave_time')  # Added to capture leave time
                    print("leave Time:", leave_time)  # Added to print start time
                    number_of_days = 'Half Day ' + leave_time

                    db.execute(
                        'INSERT INTO temp_leave (employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (employee_id, lea_section_code, leave_type,startdate, startdate, number_of_days, department_code))

                elif lea_duration == 'timeoff':
                    start_time = request.form.get('start_time')  # Added to capture start time
                    end_time = request.form.get('end_time')
                    # Convert time strings to datetime objects
                    start_time1 = datetime.strptime(start_time, '%H:%M')
                    end_time1 = datetime.strptime(end_time, '%H:%M')

                    # Convert the time difference to fractional days
                    time_difference = (end_time1 - start_time1).total_seconds() / (60 * 60)

                    number_of_days = str(time_difference) + ' Hours'

                    db.execute(
                        'INSERT INTO temp_leave (employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (employee_id, lea_section_code, leave_type,startdate, startdate, number_of_days, department_code))

                elif lea_duration == 'full_day':

                    # Convert date strings to datetime objects
                    start = datetime.strptime(startdate, '%d %m %Y')
                    end = datetime.strptime(enddate, '%d %m %Y')

                    public_holidays = set()
                    cursor.execute('SELECT date FROM public_holidays')
                    public_holidays_data = cursor.fetchall()
                    for holiday in public_holidays_data:
                        public_holidays.add(parser.parse(holiday['date']).date())

                    calculated_number_of_days = 0
                    # Loop through each day and check conditions
                    current_date = start
                    while current_date <= end:
                        # Check if the date is not a Sunday and not in public holidays
                        # if current_date.weekday() != 6 and current_date.date() not in public_holidays:
                        if current_date.weekday() not in (5, 6) and current_date.date() not in public_holidays:  # Exclude Saturdays (5) and Sundays (6)
                            calculated_number_of_days += 1

                        current_date += timedelta(days=1)


                    calculated_number_of_days = str(calculated_number_of_days) + ' Days'
                    db.execute(
                        'INSERT INTO temp_leave (employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (employee_id, lea_section_code, leave_type,startdate, enddate, calculated_number_of_days, department_code))
            else:
                flash("You have already applied for this date. Cannot proceed. Please check your leave history",'admin_employee')
            cerdepartment_code = get_department_code_by_username(user['name'])  # Replace with your actual method to get the department code

            if cerdepartment_code == 1000:
                # User's department code is 1000, select all projects
                pro_cur = db.execute('SELECT entryID, projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
            else:
                # User's department code is not 1000, select projects based on est_project_id
                pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE projectID = ?', (0,))

            if cerdepartment_code == 1000:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
            else:
                pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))


            temp_leave = []
            for pro_row in pleav_cur.fetchall():
                pro_dict = dict(pro_row)
                temp_leave.append(pro_dict)

            allpro = []
            for pro_row in pro_cur.fetchall():
                pro_dict = dict(pro_row)
                allpro.append(pro_dict)
            workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
            workingHours_allpro = []
            for pro_row in workingHours_pro_cur.fetchall():
                pro_dict = dict(pro_row)
                workingHours_allpro.append(pro_dict)
            username = user['name']
            department_code = get_department_code_by_username(username)
            client_suggestions = get_client_names()
            tempclientname = request.form.get('temp_client_name')

            project_id_suggestions = get_project_ids_by_client(tempclientname)
            project_names_suggestions = get_project_names()
            current_date = datetime.now().date()
            min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
            enquiry_project_id_suggestions = get_enquires_project_ids_by_client(tempclientname)
            enquiry_client_suggestions = get_enuiry_client_names()
            enquiry_project_ids = get_enquiry_project_ids()
            enquiry_project_names_suggestions = get_enquiry_project_names()
            enuiry_ids = get_enuiry_ids()
            is_pm = is_pm_for_project(user['name'])
            is_pe = is_pe_for_project(user['name'])
            if depart == 1002:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ? ', (1004,))
            elif depart == 1005:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (1010,))
            elif depart == 1007:
                cursor.execute('SELECT username FROM admin_user WHERE department_code = ?', (1009,))
            else:
                cursor.execute('SELECT username FROM admin_user WHERE department_code >= ?', (depart,))

            usernames1 = [row[0] for row in cursor.fetchall()]
            usernames = sorted(usernames1, key=lambda x: x.lower())
            if user['name'] not in usernames:
                usernames.append(user['name'])


            db.commit()
            show = 7
            show2 = 2
            return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
            client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,workingHours_allpro=workingHours_allpro, project_names_suggestions=project_names_suggestions,
                                enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,
                                is_pm=is_pm,is_pe=is_pe,enquiry_project_names_suggestions = enquiry_project_names_suggestions, allpro=allpro,temp_leave=temp_leave,show= show, show2 = show2)

    cerdepartment_code = get_department_code_by_username(user['name'])

    if cerdepartment_code == 1000:
        pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours')
    else:
        pro_cur = db.execute('SELECT entryID,projectID, departmentID, employeeID, project_name, client, workingDate, hoursWorked, section_code FROM temp_workingHours WHERE user = ?', (user['name'],))

    if cerdepartment_code == 1000:
        pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave')
    else:
        pleav_cur = db.execute('SELECT id, employeeID, section_code,leave_type, start_date, end_date, number_of_days, department_code FROM temp_leave WHERE employeeID = ?', (user['name'],))

    temp_leave = []
    for pro_row in pleav_cur.fetchall():
        pro_dict = dict(pro_row)
        temp_leave.append(pro_dict)

    allpro = []
    for pro_row in pro_cur.fetchall():
        pro_dict = dict(pro_row)
        allpro.append(pro_dict)

    workingHours_pro_cur = db.execute('SELECT workingDate, hoursWorked FROM workingHours WHERE employeeID = ?', (user['name'],))
    workingHours_allpro = []
    for pro_row in workingHours_pro_cur.fetchall():
        pro_dict = dict(pro_row)
        workingHours_allpro.append(pro_dict)

    username = user['name']
    department_code = get_department_code_by_username(username)
    client_suggestions = get_client_names()
    tempclientname = request.form.get('temp_client_name')
    project_id_suggestions = get_project_ids_by_client(tempclientname)
    project_names_suggestions = get_project_names()
    current_date = datetime.now().date()
    min_date = (current_date - timedelta(days=15)).strftime('%Y-%m-%d')
    eqtempclientname = request.form.get('temp_client_name_est')
    enquiry_project_id_suggestions = get_enquires_project_ids_by_client(eqtempclientname)
    enquiry_client_suggestions = get_enuiry_client_names()
    enquiry_project_ids = get_enquiry_project_ids()
    enquiry_project_names_suggestions = get_enquiry_project_names()
    enuiry_ids = get_enuiry_ids()

    EmployeeID = user['name']
    leave_types = ['Madical', 'Casual', 'Annual', 'Maternity', 'Paternity', 'Public']

    # Initialize eligibility_dict with leave types and zero values
    eligibility_dict = {leave_type: 0 for leave_type in leave_types}

    # Retrieve data from the database
    cursor.execute('SELECT * FROM admin_leave_allocation WHERE EmployeeID = ?', (EmployeeID,))
    employee_leave_eligibility_data = cursor.fetchall()

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


    cursor.execute('''SELECT leave_type, COUNT(*) AS leave_count FROM leaves WHERE employeeID = ? GROUP BY leave_type''', (EmployeeID,))
    employee_leave_used_data = cursor.fetchall()

    used_dict = {row['leave_type']: row['leave_count'] for row in employee_leave_used_data}

    if 'Madical' in eligibility_dict:
        eligibility_dict['Medical'] = eligibility_dict.pop('Madical')
    table_rows = []
    # Iterate through leave types and populate the table
    for leave_type in eligibility_dict:
        eligibility = eligibility_dict.get(leave_type, 0)
        used = used_dict.get(leave_type, 0)
        left = eligibility - used

        # Append a tuple representing a table row
        table_rows.append((leave_type, eligibility, used, left))

    for i, row in enumerate(table_rows):
        if row[0] == 'Madical':
            table_rows[i] = ('Medical', *row[1:])

    print("........client_suggestions.............",client_suggestions)
    return render_template('admin_templates/projects/admin_time_sheet.html', user=user, current_date=current_date, min_date=min_date,department_code=department_code,usernames=usernames,enuiry_ids=enuiry_ids,
    client_suggestions=client_suggestions, project_id_suggestions=project_id_suggestions,project_names_suggestions=project_names_suggestions, allpro=allpro,workingHours_allpro=workingHours_allpro,
    enquiry_project_id_suggestions=enquiry_project_id_suggestions, enquiry_client_suggestions=enquiry_client_suggestions, enquiry_project_ids=enquiry_project_ids,is_pm=is_pm,is_pe=is_pe,
    enquiry_project_names_suggestions = enquiry_project_names_suggestions, temp_leave=temp_leave,table_rows=table_rows)



@app.route('/claiminfo', methods=['GET', 'POST'])
@login_required
def claiminfo():
    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    cursor = db.cursor()
    project_id = request.args.get('project_id', type=int)

    cursor.execute("""SELECT ROUND(SUM(total), 2) AS budget FROM pmtable WHERE project_id = ?  """, (project_id,))
    result = cursor.fetchone()[0]
    budget = result if result else 0

    cursor.execute("""SELECT ROUND(SUM(total), 2) AS total_sum FROM manual_entry WHERE project_id = ? """, (project_id,))
    spentcur = cursor.fetchone()[0]
    spent = spentcur if spentcur else 0


    cursor.execute("""SELECT department_code, SUM(total) AS budget FROM pmtable WHERE project_id = ? GROUP BY department_code""", (project_id,))
    budget_data = cursor.fetchall()
    cursor.execute("""SELECT department_code, SUM(total) AS spent FROM manual_entry WHERE project_id = ? GROUP BY department_code""", (project_id,))
    spent_data = cursor.fetchall()



    # print(".........projectid.........", project_id)
    cursor_open = db.execute("SELECT claim_no FROM claimed_items WHERE projectid = ?", (project_id,))
    open_claims = cursor_open.fetchall()

    # Extract claim_no values into a list
    claim_nos = [claim[0] for claim in open_claims]
    # print("Claim Numbers:", claim_nos)

    claim_nos = list(set(claim_nos))
    # print("Claim Numbers without duplicates:", claim_nos)



    # Initialize an empty list to store claim information
    claims = []

    # Iterate through each claim_id
    for claim_id in claim_nos:
        # Execute SQL query to fetch the row information for each claim_id
        cursor_claim_info = db.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
        claim_info = cursor_claim_info.fetchone()

        # Append the row information to the list
        claims.append(claim_info)

    # print("Claim Information:", claims)

    budget_df = pd.DataFrame(budget_data, columns=['department_code', 'budget'])
    spent_df = pd.DataFrame(spent_data, columns=['department_code', 'spent'])

    merged_df = pd.merge(budget_df, spent_df, on='department_code', how='outer').fillna(0)
    merged_df['amount_left'] = merged_df['budget'] - merged_df['spent']
    merged_df = merged_df[['department_code', 'budget', 'spent', 'amount_left']]
    merged_df['department_code'] = pd.to_numeric(merged_df['department_code'])

    department_names = {range(2001, 2007): 'Materials', range(3001, 3007): 'Sub Contract', range(4001, 4005): 'Others', 5000: 'Admin'}
    summary_df = pd.DataFrame(columns=['department_name', 'spent'])

    for code_range, name in department_names.items():
        if isinstance(code_range, range):
            total_spent = merged_df.loc[merged_df['department_code'].isin(code_range), 'spent'].sum()
        else:
            total_spent = merged_df.loc[merged_df['department_code'] == code_range, 'spent'].sum()
        summary_df = pd.concat([summary_df, pd.DataFrame({'department_name': [name], 'spent': [total_spent]})], ignore_index=True)

    # print("............merged_df..........\n", merged_df)
    # print("............summary_df..........\n", summary_df)

    if merged_df.empty:
        merged_df = pd.DataFrame(columns=['department_code', 'budget', 'spent', 'amount_left'])

    if summary_df.empty:
        summary_df = pd.DataFrame(columns=['department_name', 'spent'])
        plot_data = None
    else:
        department_names = summary_df['department_name']
        spent_values = summary_df['spent']
        # print("................spent_values........\n", spent_values)

        if spent_values.sum() == 0:
            # print("not alll are zero.................")
            plot_data = None
        else:
            explode = (0.1, 0.0, 0.1, 0.0)
            colors = ['orange', 'cyan', 'brown', 'grey']
            plt.figure(figsize=(6, 4))
            plt.pie(spent_values, labels=department_names, explode=explode, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
            plt.title('Department-wise Spending', fontweight='bold', color='#004B5D')  # Make title bold and set color
            plt.axis('equal')
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
            plt.close()

    claim_no = request.args.get('no')
    # print("...............claim_no...........",claim_no)
    # Execute SQL query to fetch claim details for the given claim ID
    cursor = db.execute("SELECT * FROM claimed_items WHERE claim_no = ? AND  projectid = ?", (claim_no,project_id))
    claim_items = cursor.fetchall()
    # print("..............claim_details................\n",claim_items)



    return render_template('admin_templates/projects/claiminfo.html', user=user, department_code=department_code, project_id=project_id, budget=budget, merged_df=merged_df, plot_data=plot_data,
                           claim_items=claim_items,spent=spent,claims=claims)

@app.route('/non_po', methods=['GET', 'POST'])
@login_required
def non_po():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor = db.cursor()
    cursor.execute('SELECT id FROM projects ORDER BY id DESC')
    project_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT EnquiryNumber FROM enquiries ORDER BY EnquiryNumber DESC')
    enq_ids = [row[0] for row in cursor.fetchall()]


    cursor.execute('SELECT * FROM temp_claims WHERE claim_by = ?', (user['name'],))
    claims_data = cursor.fetchall()
    cursor.execute('SELECT DISTINCT itemname FROM claimed_items')
    itemname_suggestions = [row[0] for row in cursor.fetchall()]

    cursor.execute('SELECT DISTINCT display_name FROM vendors_details')
    vendor_suggestions = [row[0] for row in cursor.fetchall()]
    existed_claim = None
    cursor.execute('SELECT SUM(total) FROM temp_claims WHERE claim_by = ?', (user['name'],))
    total_sum = cursor.fetchone()[0]  # Fetch the total sum value

    # Round the total sum to 2 decimal places
    if total_sum  is not None:
        rounded_total_sum = round(total_sum, 2)
        # print(f'Total sum of amount for user: {rounded_total_sum}')
    else:
        rounded_total_sum = 0

    # Print the rounded total sum on the terminal
    # print(f'Total sum of amount for user: {rounded_total_sum}')

    if request.method == 'POST':
        username = user['name']
        date = request.form['date']
        Expenses = request.form['Expenses']

        # Handle projectid and project_name with fallbacks
        projectid = request.form.get('projectid', '')
        project_name = request.form.get('project_name', '')

        # If projectid and project_name are not provided, use enqid and enq_name
        if not projectid and not project_name:
            projectid = request.form.get('enqid', '')
            project_name = request.form.get('enq_name', '')

        vendor = request.form['vendor']
        Category = request.form['project']
        Sub_Category = request.form.get('Sub_Category', '')  # Use get() method with a default value
        Sub_Sub_Category = request.form.get('Sub_Sub_Category', '')
        additional_input = request.form.get('additional_input', '')
        itemname = request.form['itemname']
        invoice_number = request.form.get('invoice_number', '')

        Currency = request.form['Currency']
        Rate = request.form['Rate']

        # Safely retrieve amount and GST related fields
        amount = float(request.form['amount']) if 'amount' in request.form else 0.0
        gst_percent = request.form['gst_percent'] if 'gst_percent' in request.form else ''
        gst_value = request.form['gst_value'] if 'gst_value' in request.form else ''
        Remarks = request.form.get('Remarks', '')
        total = float(request.form['total']) if 'total' in request.form else 0.0


        # Check if gst_percent is a valid numeric value
        if 'gst_percent' in request.form and request.form['gst_percent'].strip():  # Ensure the value is not empty or whitespace
            try:
                gst_percent = float(request.form['gst_percent'])
            except ValueError:
                gst_percent = 0.0  # Default to 0.0 if the value cannot be converted to float
        else:
            gst_percent = 0.0
        # Check if gst_value is a valid numeric value
        if 'gst_value' in request.form and request.form['gst_value'].strip():  # Ensure the value is not empty or whitespace
            try:
                gst_value = float(request.form['gst_value'])
            except ValueError:
                gst_value = 0.0  # Default to 0.0 if the value cannot be converted to float
        else:
            gst_value = 0.0

        if gst_percent != 0.0:
            gst = round(amount * (gst_percent / 100.0), 2)
        elif gst_value != 0.0:
            gst = round(gst_value, 2)
        else:
            gst = 0.0
        calculated_total = amount + gst
        rounded_total = round(calculated_total, 2)

        # print("........caluculated_total.................",rounded_total)
        # print("........total.................",total)

        existed_claim = request.form.get('existed_claim', '')

        category_mapping = {'2000': 'Material', '3000': 'Sub-Con', '4000': 'Category 400', '500': 'Others', '501': 'Admin',
            '502': 'Salary',
            '503': 'Levy',
            '504': 'CPF',
            '505': 'Asset',
            '506': 'Vehicle',
            '507': 'Training',
            '508': 'Insurance',
            '509': 'Renewal',
            '510': 'Utilities',
            '511': 'Medical',
            '512': 'Travel',
            '513': 'Rental',
            '514': 'Safety',
            '515': 'Food',
            '516': 'Entertainment',
            '517': 'Others'}

        sub_category_mapping = {
            '2001': 'Mechanical',
            '2002': 'Electrical',
            '2003': 'Instruments',
            '2004': 'PLC, Software, Hardware',
            '2005': 'Consumable',
            '2006': 'Panel Hardware',
            '2007': 'Tools',
            '2008': 'Civil',
            '3001': 'Scaffolding',
            '3002': 'Programming',
            '3003': 'E&I Fabrication',
            '3004': 'Mechanical Fabrication',
            '3005': 'Manpower Supply',
            '3006': 'LEW',
            '3007': 'Calibration',
            '3008': 'Equipment Rent',
            '3009': 'Servicing',
            '3010': 'Others',
            '4001': 'Category 401',
            '4002': 'Category 402',
            '4003': 'Category 403',
            '4004': 'Category 404',
            '501': 'Admin',
            '502': 'Salary',
            '503': 'Levy',
            '504': 'CPF',
            '505': 'Asset',
            '506': 'Vehicle',
            '507': 'Training',
            '508': 'Insurance',
            '509': 'Renewal',
            '510': 'Utilities',
            '511': 'Medical',
            '512': 'Travel',
            '513': 'Rental',
            '514': 'Safety',
            '515': 'Food',
            '516': 'Entertainment',
            '517': 'Others'
        }

        sub_sub_category_mapping = {

                '11': 'Office Consumables',
                '12': 'Pantry',
                '13': 'Repair Works',
                '14': 'Furniture',
                '15': 'Others',

                '21': 'Basic',
                '22': 'Allowance',
                '23': 'Overtime',
                '24': 'Deduction',
                '25': 'Bonus',
                '26': 'Others',

                '41': 'CPF',
                '42': 'Employee',

                '51': 'Property',
                '52': 'Computers, Printer, Phone',
                '53': 'Vehicle',
                '54': 'Machines',
                '55': 'Tools',
                '56': 'Instruments',
                '57': 'Fan, Air-Con',
                '58': 'Others',

                '61': 'Loan / Rental',
                '62': 'Fuel',
                '63': 'Parking',
                '64': 'Toll',
                '65': 'Maintenance',

                '91': 'Permit Application',
                '92': 'Permit Issuance',
                '93': 'Medical Check Up',
                '94': 'Others',

                '101': 'Telephone, Internet',
                '102': 'Water, Gas, Electricity',

                '111': 'General',
                '112': 'Special',
                '113': 'Surgery',
                '114': 'Others',

                '121': 'Flight',
                '122': 'T',

                '131': 'Office',
                '132': 'Dormitory',
                '133': 'Staff Accommodation',

                '141': 'PPE',
                '142': 'Meeting',
                '143': 'Awards',
        }


        # Map category to code
        Category_name = category_mapping.get(Category, 'Unknown Category')

        # Map sub-category to code
        Sub_Category_name = sub_category_mapping.get(Sub_Category, 'Unknown Sub_Category')
        sub_Sub_Category_name = sub_sub_category_mapping.get(Sub_Sub_Category, 'Unknown Sub_Category')
        # print("............Category_name................sub_category_mapping.............",Category_name,Sub_Category_name,sub_Sub_Category_name)

        # print(f"Username: {username}")
        # print(f"Date: {date}")
        # print(f"Expenses: {Expenses}")
        # print(f"Project ID: {projectid}")
        # print(f"Project Name: {project_name}")
        # print(f"Vendor: {vendor}")
        # print(f"Category: {Category}")
        # print(f"Sub-Category: {Sub_Category}")
        # print(f"Sub-Sub-Category: {Sub_Sub_Category}")
        # print(f"Additional Input: {additional_input}")
        # print(f"Item Name: {itemname}")
        # print(f"Invoice Number: {invoice_number}")
        # print(f"Currency: {Currency}")
        # print(f"Rate: {Rate}")
        # print(f"Amount: {amount}")
        # print(f"GST %: {gst_percent}")
        # print(f"GST Value: {gst_value}")
        # print(f"Remarks: {Remarks}")
        # print(f"Existed Claim: {existed_claim}")


        try:
            sql = '''INSERT INTO temp_claims (claim_by, date, projectid, project_name, Category, Category_code, Sub_Category, Sub_Category_code, Sub_Sub_Category, Sub_Sub_Category_code, vendor, itemname,
                                                Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input)
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

            # Parameters for the INSERT statement
            params = (username, date, projectid, project_name, Category_name, Category, Sub_Category_name, Sub_Category, sub_Sub_Category_name, Sub_Sub_Category, vendor, itemname,
                     Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input)

            # Execute the INSERT statement
            cursor.execute(sql, params)
            db.commit()
            # print("data inserted,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,")
            cursor.execute('SELECT * FROM temp_claims WHERE claim_by = ?', (username,))
            claims_data = cursor.fetchall()
            cursor.execute('SELECT SUM(total) FROM temp_claims WHERE claim_by = ?', (username,))
            total_sum = cursor.fetchone()[0]  # Fetch the total sum value

            if total_sum  is not None:
                rounded_total_sum = round(total_sum, 2)
                # print(f'Total sum of amount for user: {rounded_total_sum}')
            else:
                rounded_total_sum = 0

            # Print the rounded total sum on the terminal
            # print(f'Total sum of amount for user {username}: {rounded_total_sum}')

            # Print the total sum on the terminal
            # print(f'Total sum of amount for user {username}: {total_sum}')
            # print("..............existed_claim.............",existed_claim)
            if existed_claim.strip():  # Check if existed_claim has some values
                # print("in if condtion,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,")
                # return redirect(url_for('non_po', existed_claim=existed_claim))
                return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, itemname_suggestions=itemname_suggestions, user=user, claims_data=claims_data,
                           rounded_total_sum=rounded_total_sum, existed_claim=existed_claim,vendor_suggestions=vendor_suggestions, project_ids=project_ids)
            else:
                # print("else if condtion,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,")
                return redirect(url_for('non_po'))
        except sqlite3.Error as e:
            print("SQLite error:", e)
            db.rollback()
            return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, user=user, enq_ids=enq_ids, claims_data=claims_data, project_ids=project_ids, error_message="An error occurred.")
    # print("..............enq_ids..............",enq_ids)
    return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, itemname_suggestions=itemname_suggestions, user=user, claims_data=claims_data,
                          rounded_total_sum=rounded_total_sum,enq_ids=enq_ids, vendor_suggestions=vendor_suggestions, project_ids=project_ids)


def serve_pdf_and_refresh(pdf_filename):
    # Implementing a response to serve the PDF and refresh the page
    return f'''
        <script>
            const anchor = document.createElement('a');
            anchor.href = '/download_pdf/{pdf_filename}';
            anchor.download = '{pdf_filename}';
            anchor.click();
            window.location.href = '/non_po';
        </script>
    '''

@app.route('/download_pdf/<filename>')
def download_pdf(filename):
    temp_dir = '/tmp'  # Temporary directory on the server
    pdf_path = os.path.join(temp_dir, filename)
    try:
        return send_file(pdf_path, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Error downloading PDF: {e}")
        flash(f'Error downloading PDF: {str(e)}', 'error')
        return redirect(url_for('non_po'))


def claim_to_pdf(data_list, user, current_date, overall_amount, overall_gst, overall_total, latest_claim_no):
    db = get_database()
    cursor = db.cursor()

    # Create a buffer to hold the PDF content
    pdf_buffer = BytesIO()

    # Create a canvas and generate the PDF
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    print("000000000000000000000000000000000000000000")
    c = claim_pdf(c, data_list, user,current_date, overall_total, overall_amount, overall_gst)
    print("111111111111111111111111")
    c.setFillColorRGB(0, 0, 1)
    c.setFont("Helvetica", 16)
    c.showPage()
    c.save()

    # Save the PDF locally in the Downloads folder
    # downloads_directory = os.path.join(os.path.expanduser("~"), "Downloads")
    # pdf_filename = os.path.join(downloads_directory, f'{latest_claim_no}.pdf')
    pdf_filename = f'{latest_claim_no}.pdf'
    temp_dir = '/tmp'  # Temporary directory on the server
    pdf_path = os.path.join(temp_dir, pdf_filename)

    # Ensure the directory exists
    os.makedirs(temp_dir, exist_ok=True)


    try:
        with open(pdf_path, 'wb') as pdf_file:
            pdf_file.write(pdf_buffer.getvalue())
        print(f"PDF saved34534 successfully as {pdf_path}")
        return pdf_filename
    except Exception as e:
        print(f"Error saving PDF: {e}")

    user = get_current_user()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    cursor = db.execute('SELECT * FROM temp_claims')
    claims_data = cursor.fetchall()
    db.commit()

    # Render the template
    return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, user=user, claims_data=claims_data)


from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from datetime import datetime

def claim_pdf(c, data_list, user, current_date, overall_total, overall_amount, overall_gst):
    c.translate(inch, inch)
    c.setFont("Helvetica", 10)

    image_path = 'templates/admin_templates/projects/ces.jpeg'
    image_width = 2
    image_height = 0.3
    # c.drawImage(image_path, 4.7 * inch, 9.27 * inch, width=image_width * inch, height=image_height * inch)

    curr = current_date.strftime('%d-%m-%Y')

    c.setFont("Helvetica-Bold", 15)
    c.drawString(2.2 * inch, 9.3 * inch, 'Expense Claims')

    c.setFont("Helvetica-Bold", 10)
    c.setFillColorRGB(0, 0, 0)
    print(".........1............")
    # Header lines
    c.line(0, 9.7 * inch, 6.8 * inch, 9.7 * inch)
    c.line(0, 9.25 * inch, 6.8 * inch, 9.25 * inch)
    c.line(0, 8.9 * inch, 6.8 * inch, 8.9 * inch)

    print(".........2...........")
    # Vertical Lines
    c.line(0.0 * inch, 9.7 * inch, 0.0 * inch, -0.7 * inch)
    c.line(0.4 * inch, 9.25 * inch, 0.4 * inch, -0.4 * inch)
    c.line(1.0 * inch, 9.25 * inch, 1.0 * inch, -0.4 * inch)
    c.line(1.5 * inch, 9.25 * inch, 1.5 * inch, -0.4 * inch)
    c.line(2.9 * inch, 9.25 * inch, 2.9 * inch, -0.4 * inch)
    c.line(4.8 * inch, 9.25 * inch, 4.8 * inch, -0.4 * inch)
    c.line(5.6 * inch, 9.25 * inch, 5.6 * inch, -0.7 * inch)
    c.line(6.1 * inch, 9.25 * inch, 6.1 * inch, -0.7 * inch)
    c.line(6.8 * inch, 9.7 * inch, 6.8 * inch, -0.7 * inch)
    print(".........3............")

    c.drawString(0.1 * inch, 9.5 * inch, 'Name')
    c.drawString(0.6 * inch, 9.5 * inch, str(user))
    c.drawString(0.1 * inch, 9.3 * inch, 'Date')
    c.drawString(0.6 * inch, 9.3 * inch, str(curr))
    print(".........4............")
    # Item table heading
    c.drawString(0.1 * inch, 9.0 * inch, 'S/N')
    c.drawString(0.55 * inch, 9.0 * inch, 'Date')
    c.drawString(1.05 * inch, 9.0 * inch, 'Code')
    c.drawString(1.8 * inch, 9.0 * inch, 'Type')
    c.drawString(3.5 * inch, 9.0 * inch, 'Description')
    c.drawString(4.95 * inch, 9.0 * inch, 'Amount')
    c.drawString(5.65 * inch, 9.0 * inch, 'GST%')
    c.drawString(6.3 * inch, 9.0 * inch, 'Total')
    print(".........5............")


    # Signature
    c.setFont("Helvetica-Bold", 10)
    # c.drawString(4.4 * inch, -0.6 * inch, 'Total Claim(SGD): $')
    # c.drawString(5.75 * inch, -0.6 * inch, str(overall_total))

    c.line(0, -0.4 * inch, 6.8 * inch, -0.4 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)

    c.setFont("Helvetica", 10)
    print(".........6............")

    row_height = 0.3
    current_height = 9.0
    line_height = 8.9
    print(data_list)



    for index, claim in enumerate(data_list, start=1):
        locale.setlocale(locale.LC_ALL, '')
        if index % 31 == 0:  # Add new page after every 30 items
            c.showPage()
            add_header_and_columns(c, user, current_date)
            row_height = 0.3
            current_height = 9.0
            line_height = 8.9

        current_height = current_height - row_height
        line_height = line_height - row_height
        print(".........7............")

        formatted_date = datetime.strptime(claim.get('date', ''), '%Y-%m-%d').strftime('%d/%m/%y') if 'date' in claim else ''

        c.setFont("Helvetica", 10)
        c.drawString(0.1 * inch, current_height * inch, str(index))

        # Check if 'date' exists before attempting to draw
        if 'date' in claim:
            c.drawString(0.43 * inch, current_height * inch, formatted_date)

                # Check if 'purchase_type' exists before attempting to draw
        if 'purchase_type' in claim:
            purchase_type = claim['purchase_type'][:17]  # Extract the first 18 characters
            c.drawString(1.55 * inch, current_height * inch, purchase_type)
        print(".........8............")

        # Check if 'project_id' exists before attempting to draw
        if 'project_id' in claim:
            c.drawString(1.05 * inch, current_height * inch, str(claim['project_id']))

        if 'item_name' in claim:
            c.drawString(3.0 * inch, current_height * inch, claim['item_name'][:22])
        print(".........9............")
        print(".........9............")
        # Check if 'amount' exists before attempting to draw
        if 'amount' in claim:
            try:
                amount_formatted = f"{float(claim['amount']):,.2f}"
                c.drawString(4.85 * inch, current_height * inch, amount_formatted)
            except Exception as e:
                print(f"Error occurred while formatting amount: {e}")
        print(".........10............")

        if 'gst' in claim:
            try:
                gst_value = str(float(claim['gst']))
                c.drawString(5.60 * inch, current_height * inch, gst_value)
            except Exception as e:
                print(f"Error occurred while formatting GST: {e}")
        print(".........11............")

        if 'total' in claim:
            try:
                total_formatted = f"{float(claim['total']):,.2f}"
                c.drawString(6.11 * inch, current_height * inch, total_formatted)
            except Exception as e:
                print(f"Error occurred while formatting Total: {e}")
        print(".........12............")

        c.line(0, line_height * inch, 6.8 * inch, line_height * inch)

    # Signature
    c.setFont("Helvetica-Bold", 8)
    # c.drawString(4.4 * inch, -0.6 * inch, 'Total Claim(SGD): $')
    # c.drawString(5.75 * inch, -0.6 * inch, str(overall_total))
    print(".........13............")
    try:
        overall_total_float = float(overall_total)
        print(".................overall_gst........................",overall_gst)
        overall_gst_float = float(overall_gst)
        print(".................overall_gst_float........................",overall_gst_float)
        overall_amount_float = float(overall_amount)
        print(".........14............")
        total_formatted = locale.format_string("%0.2f", overall_total_float, grouping=True)
        amont_formatted = locale.format_string("%0.2f", overall_amount_float, grouping=True)

        gst_formatted = locale.format_string("%0.2f", overall_gst_float, grouping=True)
        print(".................gst_formatted........................",gst_formatted)
        c.drawString(2.0 * inch, -0.6 * inch, 'Total (SGD): $')
        c.drawString(4.95 * inch, -0.6 * inch, amont_formatted)
        c.drawString(5.60 * inch, -0.6 * inch, gst_formatted)
        c.drawString(6.15 * inch, -0.6 * inch, total_formatted)
    except Exception as e:
        print(f"Error occurred while formatting Overall Total: {e}")
    print(".........1............")

    c.line(0, -0.4 * inch, 6.8 * inch, -0.4 * inch)
    c.line(0, -0.7 * inch, 6.8 * inch, -0.7 * inch)

    return c

def add_header_and_columns(c, user, current_date):
    c.translate(inch, inch)
    c.setFont("Helvetica", 10)

    image_path = 'templates/admin_templates/projects/ces.jpeg'
    image_width = 2
    image_height = 0.3
    # c.drawImage(image_path, 4.7 * inch, 9.27 * inch, width=image_width * inch, height=image_height * inch)

    use = user
    curr = current_date.strftime('%d-%m-%Y')

    c.setFont("Helvetica-Bold", 15)
    c.drawString(2 * inch, 9.3 * inch, 'Expenses Claim Form')

    c.setFont("Helvetica-Bold", 10)
    c.setFillColorRGB(0, 0, 0)

    # Header lines
    c.line(0, 9.7 * inch, 6.8 * inch, 9.7 * inch)
    c.line(0, 9.25 * inch, 6.8 * inch, 9.25 * inch)
    c.line(0, 8.9 * inch, 6.8 * inch, 8.9 * inch)

    # Vertical Lines
    c.line(0.0 * inch, 9.7 * inch, 0.0 * inch, -0.7 * inch)
    c.line(0.4 * inch, 9.25 * inch, 0.4 * inch, -0.4 * inch)
    c.line(1.0 * inch, 9.25 * inch, 1.0 * inch, -0.4 * inch)
    c.line(1.5 * inch, 9.25 * inch, 1.5 * inch, -0.4 * inch)
    c.line(2.9 * inch, 9.25 * inch, 2.9 * inch, -0.4 * inch)
    c.line(4.8 * inch, 9.25 * inch, 4.8 * inch, -0.4 * inch)
    c.line(5.6 * inch, 9.25 * inch, 5.6 * inch, -0.7 * inch)
    c.line(6.1 * inch, 9.25 * inch, 6.1 * inch, -0.7 * inch)
    c.line(6.8 * inch, 9.7 * inch, 6.8 * inch, -0.7 * inch)

    c.drawString(0.1 * inch, 9.5 * inch, 'Name')
    c.drawString(0.6 * inch, 9.5 * inch, str(user))
    c.drawString(0.1 * inch, 9.3 * inch, 'Date')
    c.drawString(0.6 * inch, 9.3 * inch, str(curr))

    # Item table heading
    c.drawString(0.1 * inch, 9.0 * inch, 'S/N')
    c.drawString(0.55 * inch, 9.0 * inch, 'Date')
    c.drawString(1.05 * inch, 9.0 * inch, 'Code')
    c.drawString(1.8 * inch, 9.0 * inch, 'Type')
    c.drawString(3.5 * inch, 9.0 * inch, 'Description')
    c.drawString(4.95 * inch, 9.0 * inch, 'Amount')
    c.drawString(5.65 * inch, 9.0 * inch, 'GST%')
    c.drawString(6.3 * inch, 9.0 * inch, 'Total')


    c.setFont("Helvetica", 10)

@app.route('/generate_claim', methods=['GET', 'POST'])
@login_required
def generate_claim():
    if request.method == 'POST':
        db = get_database()
        cursor = db.cursor()
        data_list = []

        if 'Claim' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            overall_amount = 0.0
            overall_gst = 0.0
            overall_total = 0.0

            cursor.execute('SELECT id FROM claims ORDER BY id DESC LIMIT 1')
            result = cursor.fetchone()
            current_year = datetime.now().year

            existed_claim = request.form.get('Claim')

            if existed_claim and existed_claim.strip():
                parts = existed_claim.split('-')
                if len(parts) == 3:
                    prefix, year_part, claim_no_part = parts
                    latest_claim_no = f"{existed_claim}-01"
                elif len(parts) == 4:
                    prefix, year_part, claim_no_part, revision = parts
                    new_revision = int(revision) + 1
                    formatted_revision = f"{new_revision:02}"
                    latest_claim_no = f"{prefix}-{year_part}-{claim_no_part}-{formatted_revision}"

                cursor.execute('DELETE FROM claims WHERE claim_id = ?', (existed_claim,))
                cursor.execute('DELETE FROM claimed_items WHERE claim_no = ?', (existed_claim,))

            else:
                if result:
                    lat_claim_no = result[0]
                else:
                    lat_claim_no = 0
                temp_claim_no = lat_claim_no + 1
                latest_claim_no = f"C-{str(current_year)[-2:]}-{temp_claim_no}"
                print(".............latest_claim_no.....................",latest_claim_no)

            try:

                for claim_id in claimdata:
                    print("..claim_id..............",claim_id)
                    cursor.execute('SELECT * FROM temp_claims WHERE id = ?', (claim_id,))
                    existing_data = cursor.fetchone()
                    if existing_data:
                        columns = [col[0] for col in cursor.description]
                        claim_data = dict(zip(columns, existing_data))

                        overall_amount += float(claim_data['amount'])
                        overall_gst += float(claim_data['gst'])
                        overall_total += float(claim_data['total'])

                        cursor.execute('''
                            INSERT INTO claimed_items (claim_by, date, projectid, project_name, Category, Category_code,Sub_Category, Sub_Category_code, Sub_Sub_Category, Sub_Sub_Category_code,
                                                    vendor, itemname, Currency, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input, claim_no)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (claim_data['claim_by'], claim_data['date'], claim_data['projectid'], claim_data['project_name'],claim_data['Category'], claim_data['Category_code'], claim_data['Sub_Category'],
                            claim_data['Sub_Category_code'], claim_data['Sub_Sub_Category'], claim_data['Sub_Sub_Category_code'],claim_data['vendor'], claim_data['itemname'], claim_data['Currency'],
                            claim_data['Rate'], claim_data['invoice_number'], claim_data['amount'], claim_data['gst_percent'], claim_data['gst_value'], claim_data['Remarks'], claim_data['gst'],
                            claim_data['total'], claim_data['additional_input'], latest_claim_no))

                        cursor.execute('DELETE FROM temp_claims WHERE id = ?', (claim_id,))

                        # Store data in the dictionary
                        data_dict = { 'date': claim_data['date'], 'project_id': claim_data['projectid'], 'item_name': claim_data['itemname'], 'purchase_type': claim_data['Category'],
                            'amount': claim_data['amount'],'gst': claim_data['gst'],'total': claim_data['total'] }
                        data_list.append(data_dict)
                        db.commit()

                user = get_current_user()['name']
                current_date = datetime.now().date()
                overall_total = round(overall_total, 2)
                overall_amount = round(overall_amount, 2)
                overall_gst = round(overall_gst, 2)

                cursor.execute(''' INSERT INTO claims (claim_by, claim_id, claim_date, status, claim_Total) VALUES (?, ?, ?, ?, ?)''', (user, latest_claim_no, current_date, 'Open', overall_total))
                db.commit()

                pdf_filename = claim_to_pdf(data_list, user, current_date, overall_amount, overall_gst, overall_total, latest_claim_no)

                if pdf_filename:
                    db.commit()
                    # Serve the PDF directly
                    return serve_pdf_and_refresh(pdf_filename)
                else:
                    db.rollback()
                    flash('Error generating PDF', 'error')
                    return redirect(url_for('non_po'))

            except Exception as e:
                db.rollback()
                flash(f'Error generating claims: {str(e)}', 'error')
                return redirect(url_for('non_po'))

        if 'Delete' in request.form:
            claimdata = request.form.getlist('claimdata[]')
            try:
                for claim_id in claimdata:
                    print("yes")
                    cursor.execute('DELETE FROM temp_claims WHERE id = ?', (claim_id,))

                db.commit()
                flash('Selected claims deleted successfully.', 'success')
            except Exception as e:
                db.rollback()
                flash(f'Error deleting claims: {str(e)}', 'error')
    print("gopiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii")
    return redirect(url_for('non_po'))

@app.route('/deletenonpo/<int:claimid>', methods=["GET", "POST"])
@login_required
def deletenonpo(claimid):
    user = get_current_user()
    if request.method == 'GET':
        db = get_database()
        db.execute('DELETE FROM temp_claims WHERE id = ?', [claimid])
        db.commit()
        return redirect(url_for('non_po'))
    return render_template('non_po.html', user=user)

@app.route('/user_claims', methods=['GET', 'POST'])
@login_required
def user_claims():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    username = user['name']
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])
    db = get_database()
    cursor = db.cursor()

    # Check if there are any records in the temp_claims table for the current user
    cursor_temp = db.execute("SELECT COUNT(*) FROM temp_claims WHERE claim_by = ?", (username,))
    temp_claims_count = cursor_temp.fetchone()

    if temp_claims_count is not None:
        lat_claim_no = temp_claims_count[0]
        if lat_claim_no != 0:
            data_in_temp_table = 'True'
        else:
            data_in_temp_table = 'False'

    cursor_open = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND (status = 'Open' OR status = 'Rework') AND claim_by = ? ORDER BY id DESC",(username,))
    # Select rows with status "approved" for the last two months ordered by descending ID
    cursor_approved = db.execute("SELECT * FROM claims WHERE claim_date >= DATE('now', '-2 months') AND status = 'Approved' AND claim_by = ? ORDER BY id DESC",(username,))
    # Fetch the results
    open_claims = cursor_open.fetchall()
    approved_claims = cursor_approved.fetchall()
    # Combine the results
    my_claims = open_claims + approved_claims

    claim_no = request.args.get('no')

    cursor = db.execute('SELECT * FROM claimed_items WHERE claim_no = ? ORDER BY id DESC', (claim_no,))
    claim_items = cursor.fetchall()


    return render_template('admin_templates/projects/claim_list.html', is_pm=is_pm, department_code=department_code, claim_items=claim_items,user=user,my_claims=my_claims,data_in_temp_table=data_in_temp_table)

@app.route('/claim_editlist', methods=['GET', 'POST'])
@login_required
def claim_editlist():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    cursor = db.cursor()
    is_pm = is_pm_for_project(user['name'])
    department_code = get_department_code_by_username(user['name'])

    if request.method == 'GET':
        claim_no = request.args.get('no')
        existed_claim = claim_no
        # print("..==============================================================================================.......claim_no.............",claim_no)
        cursor = db.execute("SELECT * FROM claimed_items WHERE claim_no = ?", (claim_no,))
        data = cursor.fetchall()
        db.execute('DELETE  FROM temp_claims WHERE claim_by= ?', (user['name'],) )

        # Assuming 'data' is a list of dictionaries containing the relevant data

        for item in data:
            db.execute('''
                INSERT INTO temp_claims (claim_by, date, projectid, project_name, Category, Category_code, Sub_Category, Sub_Category_code, Sub_Sub_Category, Sub_Sub_Category_code,
                                        vendor, itemname, Currency, comments, Rate, invoice_number, amount, gst_percent, gst_value, Remarks, gst, total, additional_input, claim_no)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)''',
                (item['claim_by'], item['date'], item['projectid'], item['project_name'], item['Category'], item['Category_code'], item['Sub_Category'], item['Sub_Category_code'],
                item['Sub_Sub_Category'], item['Sub_Sub_Category_code'], item['vendor'], item['itemname'], item['Currency'], item['comments'], item['Rate'], item['invoice_number'],
                item['amount'], item['gst_percent'], item['gst_value'], item['Remarks'], item['gst'], item['total'], item['additional_input'], item['claim_no']))

        cursor = db.execute('SELECT * FROM temp_claims WHERE claim_by= ?', (user['name'],) )
        claims_data = cursor.fetchall()
        db.commit()


        cursor.execute('SELECT id FROM projects')
        project_ids = [row[0] for row in cursor.fetchall()]
        return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, user=user, claims_data=claims_data, project_ids=project_ids,existed_claim=existed_claim)

    # For the POST request, initialize variables to avoid undefined error
    claims_data = None
    project_ids = None

    return render_template('admin_templates/projects/non_po.html', is_pm=is_pm, department_code=department_code, user=user, claims_data=claims_data, project_ids=project_ids)

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



#------------------------------------------------------------------------settings--------------------------------------------------------------------

@app.route('/settings')
@login_required
def settings():
    return render_template('admin_templates/settings/settings_main_page.html')

@app.route('/controls', methods=['GET', 'POST'])
@login_required
def controls():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    project_id = request.args.get('projectId', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]

    return render_template('admin_templates/settings/controls.html', project_ids=project_ids,is_pm=is_pm, department_code=department_code, user=user, project_id=project_id,project_details=project_details)

@app.route('/office', methods=['GET', 'POST'])
@login_required
def office():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = get_current_user()
    db = get_database()
    department_code = get_department_code_by_username(user['name'])
    is_pm = is_pm_for_project(user['name'])

    # Get projectId from query parameters
    project_id = request.args.get('projectId', type=int)
    cursor = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    project_details = cursor.fetchone()
    cursor.execute('SELECT id FROM projects')
    project_ids = [row[0] for row in cursor.fetchall()]

    return render_template('admin_templates/settings/office.html', project_ids=project_ids,is_pm=is_pm, department_code=department_code, user=user, project_id=project_id,project_details=project_details)

#----------------------------------------------------------------------MAIN PROGRAM----------------------------------------------------------------
if __name__ =='__main__' :
    app.run(debug = True, host = "0.0.0.0", port = 5000)
    # webview.start()

# if __name__ == '__main__':
#     app.run(debug=True, port=5002)



