from flask import Flask, render_template, session, request, Response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime, timedelta
import requests
import settings
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = settings.secret_key
app.config.from_object(settings.configClass)
db = SQLAlchemy(app)


# ============================================
# Logging
# ============================================

formatter = logging.Formatter(settings.LOG_FORMAT)
handler = RotatingFileHandler(
    settings.LOG_FILE,
    maxBytes=settings.LOG_MAX_BYTES,
    backupCount=settings.LOG_BACKUP_COUNT
)
handler.setLevel(logging.getLevelName(settings.LOG_LEVEL))
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# ============================================
# DB Model
# ============================================


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    refresh_key = db.Column(db.String)
    expires_in = db.Column(db.String)

    def __init__(self, user_id, refresh_key, expires_in):
        self.user_id = user_id
        self.refresh_key = refresh_key
        self.expires_in = expires_in

    def __repr__(self):
        return '<User %r>' % self.user_id


# ============================================
# Utility Functions
# ============================================

def error(exception=None):
    return Response(
        render_template(
            'error.htm.j2',
            message=exception.get(
                'exception',
                'Please contact your System Administrator.'
            )
        )
    )


def check_valid_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """
        Decorator to check if the user is allowed access to the app.

        If user is allowed, return the decorated function.
        Otherwise, return an error page with corresponding message.
        """
        if request.form:
            session.permanent = True
            # 1 hour long session
            app.permanent_session_lifetime = timedelta(minutes=60)
            session['course_id'] = request.form.get('custom_canvas_course_id')
            session['canvas_user_id'] = request.form.get('custom_canvas_user_id')
            roles = request.form['roles']

            if "Administrator" in roles:
                session['admin'] = True
                session['instructor'] = True
            elif 'admin' in session:
                # remove old admin key in the session
                session.pop('admin', None)

            if "Instructor" in roles:
                session['instructor'] = True
            elif 'instructor' in session:
                # remove old instructor key from the session
                session.pop('instructor', None)

        # no session and no request
        if not session:
            if not request.form:
                app.logger.warning("No session and no request. Not allowed.")
                return render_template(
                    'error.htm.j2',
                    msg='Not session or request provided.'
                )

        # no canvas_user_id
        if not request.form.get('custom_canvas_user_id') and 'canvas_user_id' not in session:
            app.logger.warning("No canvas user ID. Not allowed.")
            return render_template(
                'error.htm.j2',
                msg='No canvas user ID provided.'
            )

        # no course_id
        if not request.form.get('custom_canvas_course_id') and 'course_id' not in session:
            app.logger.warning("No course ID. Not allowed.")
            return render_template(
                'error.htm.j2',
                msg='No course_id provided.'
            )

        return f(*args, **kwargs)
    return decorated_function


# ============================================
# Web Views / Routes
# ============================================


@app.route('/index', methods=['POST', 'GET'])
def index():
    # Cool, we got through
    msg = "hi!"
    session['course_id'] = request.form.get('custom_canvas_course_id')
    session['user_id'] = request.form.get('custom_canvas_user_id')

    return render_template('index.htm.j2', msg=msg)


# OAuth login
# Redirect URI


@app.route('/oauthlogin', methods=['POST', 'GET'])
def oauth_login():
    code = request.args.get('code')
    payload = {
        'grant_type': 'authorization_code',
        'client_id': settings.oauth2_id,
        'redirect_uri': settings.oauth2_uri,
        'client_secret': settings.oauth2_key,
        'code': code
    }
    r = requests.post(settings.BASE_URL+'login/oauth2/token', data=payload)

    if r.status_code == 500:
        # Canceled oauth or server error
        if 'canvas_user_id' in session and 'course_id' in session:
            app.logger.error(
                '''Status code 500 from oauth, authentication error\n
                User ID: {} Course: {} \n {} \n Request headers: {}'''.format(
                    session['canvas_user_id'], session['course_id'],
                    r.url, r.headers
                )
            )
        else:
            app.logger.error(
                '''Status code 500 from oauth, authentication error\n
                User ID: None Course: None \n {} \n Request headers: {}'''.format(
                    r.url, r.headers
                )
            )

        msg = '''Authentication error,
            please refresh and try again. If this error persists,
            please contact support.'''
        return render_template("error.htm.j2", msg=msg)

    if 'access_token' in r.json():
        session['api_key'] = r.json()['access_token']

        if 'refresh_token' in r.json():
            session['refresh_token'] = r.json()['refresh_token']

        if 'expires_in' in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = datetime.now()
            expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
            session['expires_in'] = expires_in
        try:

            # add to db
            new_user = Users(
                session['canvas_user_id'],
                session['refresh_token'],
                session['expires_in']
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(
                "Error in adding new user to db: \n {} {} {} {} ".format(
                    e, session['canvas_user_id'], session['refresh_token'], session['expires_in']
                )
            )
            msg = '''Authentication error,
            please refresh and try again. If this error persists,
            please contact support.'''
            return render_template("error.htm.j2", msg=msg)

    app.logger.warning(
        "Some other error\n User: {} Course: {} \n {} \n Request headers: {} \n {}".format(
            session['canvas_user_id'], session['course_id'],
            r.url, r.headers, r.json()
        )
    )
    msg = '''Authentication error,
        please refresh and try again. If this error persists,
        please contact support.'''
    return render_template("error.htm.j2", msg=msg)


@app.route('/launch', methods=['POST', 'GET'])
@check_valid_user
def launch():

    # if they aren't in our DB/their token is expired or invalid
    try:
        user = Users.query.filter_by(user_id=int(session['canvas_user_id'])).first()
        # get or add
        if user is not None:

            expiration_date = datetime.strptime(user.expires_in, '%Y-%m-%d %H:%M:%S.%f')

            refresh_token = user.refresh_key
            if datetime.now() > expiration_date or 'api_key' not in session:
                # expired! Use the refresh token
                app.logger.info(
                    '''Expired refresh token or api_key not in session\n
                    User: {} \n Expiration date in db: {}'''.format(user.user_id, user.expires_in)
                )
                payload = {
                    'grant_type': 'refresh_token',
                    'client_id': settings.oauth2_id,
                    'redirect_uri': settings.oauth2_uri,
                    'client_secret': settings.oauth2_key,
                    'refresh_token': refresh_token
                }
                r = requests.post(settings.BASE_URL+'login/oauth2/token', data=payload)
                if 'access_token' in r.json():
                    session['api_key'] = r.json()['access_token']
                    app.logger.info(
                        "New access token created\n User: {}".format(user.user_id)
                    )

                    if 'refresh_token' in r.json():
                        session['refresh_token'] = r.json()['refresh_token']

                    if 'expires_in' in r.json():
                        # expires in seconds
                        # add the seconds to current time for expiration time
                        current_time = datetime.now()
                        expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
                        session['expires_in'] = expires_in
                    try:
                        user.expires_in = session['expires_in']
                        db.session.commit()
                    except Exception as e:
                        # log error
                        app.logger.error(
                            '''Error in updating user in the db:\n {} \n user ID {} \n
                            Refresh token {} \n Oauth expiration in session {}'''.format(
                                session['canvas_user_id'],
                                session['refresh_token'],
                                session['expires_in']
                            )
                        )
                        msg = '''Authentication error,
                            please refresh and try again. If this error persists,
                            please contact support.'''
                        return render_template("error.htm.j2", msg=msg)

                    return redirect(url_for('index'))
            else:
                # good to go!
                # test the api key
                auth_header = {'Authorization': 'Bearer ' + session['api_key']}
                r = requests.get(settings.API_URL + 'users/%s/profile' %
                                 (session['canvas_user_id']), headers=auth_header)
                # check for WWW-Authenticate
                # https://canvas.instructure.com/doc/api/file.oauth.html
                if 'WWW-Authenticate' not in r.headers and r.status_code != 401:
                    return redirect(url_for('index'))
                else:
                    app.logger.info(
                        '''Reauthenticating: \n User ID: {} \n Course: {}
                        Refresh token: {} \n
                        Oauth expiration in session: {} \n {} \n {} \n {}'''.format(
                            session['canvas_user_id'], session['course_id'],
                            session['refresh_token'], session['expires_in'],
                            r.status_code, r.url, r.headers
                        )
                    )
                    return redirect(
                        settings.BASE_URL+'login/oauth2/auth?client_id=' +
                        settings.oauth2_id + '&response_type=code&redirect_uri=' +
                        settings.oauth2_uri
                    )
                app.logger.error(
                    '''Some other error: \n
                    User ID: {}  Course: {} \n Refresh token: {} \n
                    Oauth expiration in session: {} \n {} \n {} \n {} {}'''.format(
                        session['canvas_user_id'], session['course_id'],
                        session['refresh_token'], session['expires_in'], r.status_code,
                        r.url, r.headers, r.json()
                    )
                )
                msg = '''Authentication error,
                    please refresh and try again. If this error persists,
                    please contact support.'''
                return render_template("error.htm.j2", msg=msg)
        else:
            # not in db, go go oauth!!
            app.logger.info(
                "Person doesn't have an entry in db, redirecting to oauth: {}".format(
                    session['canvas_user_id']
                )
            )
            return redirect(settings.BASE_URL+'login/oauth2/auth?client_id='+settings.oauth2_id +
                            '&response_type=code&redirect_uri='+settings.oauth2_uri)
    except Exception as e:
        # they aren't in the db, so send em to the oauth stuff
        app.logger.info(
            "Error getting a person from the db, reuathenticating: {} {}".format(
                session['canvas_user_id'], e
            )
        )
        return redirect(settings.BASE_URL+'login/oauth2/auth?client_id='+settings.oauth2_id +
                        '&response_type=code&redirect_uri='+settings.oauth2_uri)
    app.logger.warning(
        "Some other error, {} {}".format(
            session['canvas_user_id'],
            session['course_id']
        )
    )
    msg = '''Authentication error, please refresh and try again. If this error persists,
        please contact support.'''
    return render_template("error.htm.j2", msg=msg)


# ============================================
# XML
# ============================================

@app.route("/xml/", methods=['GET'])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    try:
        return Response(render_template(
            'lti.xml.j2'), mimetype='application/xml'
        )
    except:
        app.logger.error("No XML file.")

        return render_template(
            'error.htm.j2', msg='''No XML file. Please refresh
            and try again. If this error persists,
            please contact support.'''
        )
