from flask import Flask,render_template,request,redirect,url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from api_key import *
import random 
import string
app = Flask(__name__)
app.secret_key = "1234"

#config SQL Alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"  
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False 
db = SQLAlchemy(app)

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)



#Database Model 
class User(db.Model):
    #class variables 
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),unique=True,nullable=False)
    password_hash = db.Column(db.String(150),nullable=False)

    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
    

#Routes 

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")


# Login 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('index.html', error='Invalid username or password.')
    return render_template('login.html')
        

# Register 
@app.route('/register',methods = ["POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template("index.html",error="User Already Exists")
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            return redirect(url_for("dashboard"))

#Dashboard 
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template("dashboard.html",username = session["username"])
    else:
        return redirect(url_for("home"))



#logout

@app.route('/logout')
def logout():
    session.pop("username")
    return redirect(url_for("home"))













#login for google 
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        username = user_info['email']

        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            user.set_password(''.join(random.choices(string.ascii_letters + string.digits, k=16)))
            db.session.add(user)
            db.session.commit()

        session['username'] = username
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error during Google authorization: {str(e)}")
        return redirect(url_for('home'))





# authorize for google



if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

