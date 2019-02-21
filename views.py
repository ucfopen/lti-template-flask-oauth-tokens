from flask import Flask, render_template, session, request, Response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import timedelta
from pylti.flask import lti
import time
import requests
import settings
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = settings.secret_key
app.config.from_object(settings.configClass)
db = SQLAlchemy(app)


# Logging
formatter = logging.Formatter(settings.LOG_FORMAT)
handler = RotatingFileHandler(
    settings.LOG_FILE,
    maxBytes=settings.LOG_MAX_BYTES,
    backupCount=settings.LOG_BACKUP_COUNT
)
handler.setLevel(logging.getLevelName(settings.LOG_LEVEL))
handler.setFormatter(formatter)
app.logger.addHandler(handler)


# DB Model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True)
    refresh_key = db.Column(db.String(255))
    expires_in = db.Column(db.BigInteger)

    def __init__(self, user_id, refresh_key, expires_in):
        self.user_id = user_id
        self.refresh_key = refresh_key
        self.expires_in = expires_in

    def __repr__(self):
        return '<User %r>' % self.user_id


# Utility Functions
def return_error(msg):
    return render_template('error.htm.j2', msg=msg)


def error(exception=None):
    app.logger.error("PyLTI error: {}".format(exception))
    return return_error('''Authentication error,
        please refresh and try again. If this error persists,
        please contact support.''')


def redirect_to_auth():
    """Redirects the user to the Canvas OAUTH flow

    This function uses BASE_URL and the oauth settings from settings.py to redirect the
    user to the appropriate place in their Canvas installation for authentication.
    """
    return redirect(
        "{}login/oauth2/auth?client_id={}&response_type=code&redirect_uri={}&scope={}".format(
            settings.BASE_URL, settings.oauth2_id, settings.oauth2_uri, settings.oauth2_scopes
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
                return return_error('No session or request provided.')

        # no canvas_user_id
        if not request.form.get('custom_canvas_user_id') and 'canvas_user_id' not in session:
            app.logger.warning("No canvas user ID. Not allowed.")
            return return_error('No canvas uer ID provided.')

        # no course_id
        if not request.form.get('custom_canvas_course_id') and 'course_id' not in session:
            app.logger.warning("No course ID. Not allowed.")
            return return_error('No course_id provided.')

        # If they are neither instructor or admin, they're not in the right place

        if 'instructor' not in session and 'admin' not in session:
            app.logger.warning("Not enrolled as Teacher or an Admin. Not allowed.")
            return return_error('''You are not enrolled in this course as a Teacher or Designer.
            Please refresh and try again. If this error persists, please contact support.''')

        return f(*args, **kwargs)
    return decorated_function


def refresh_access_token(user):
    """
    Use a user's refresh token to get a new access token.

    :param user: The user to get a new access token for.
    :type user: :class:`Users`

    :rtype: dict
    :returns: Dictionary with keys 'access_token' and 'expiration_date'.
        Values will be `None` if refresh fails.
    """
    refresh_token = user.refresh_key

    payload = {
            'grant_type': 'refresh_token',
            'client_id': settings.oauth2_id,
            'redirect_uri': settings.oauth2_uri,
            'client_secret': settings.oauth2_key,
            'refresh_token': refresh_token
        }
    response = requests.post(
        settings.BASE_URL + 'login/oauth2/token',
        data=payload
    )

    if 'access_token' not in response.json():
        app.logger.warning((
            'Access token not in json. Bad api key or refresh token.\n'
            'URL: {}\n'
            'Status Code: {}\n'
            'Payload: {}\n'
            'Session: {}'
        ).format(response.url, response.status_code, payload, session))
        return {
            'access_token': None,
            'expiration_date': None
        }

    api_key = response.json()['access_token']
    app.logger.info(
        'New access token created\n User: {0}'.format(user.user_id)
    )

    if 'expires_in' not in response.json():
        app.logger.warning((
            'expires_in not in json. Bad api key or refresh token.\n'
            'URL: {}\n'
            'Status Code: {}\n'
            'Payload: {}\n'
            'Session: {}'
        ).format(response.url, response.status_code, payload, session))
        return {
            'access_token': None,
            'expiration_date': None
        }

    current_time = int(time.time())
    new_expiration_date = current_time + response.json()['expires_in']

    # Update expiration date in db
    user.expires_in = new_expiration_date
    db.session.commit()

    # Confirm that expiration date has been updated
    updated_user = Users.query.filter_by(user_id=int(user.user_id)).first()
    if updated_user.expires_in != new_expiration_date:
        readable_expires_in = time.strftime(
            '%a, %d %b %Y %H:%M:%S',
            time.localtime(updated_user.expires_in)
        )
        readable_new_expiration = time.strftime(
            '%a, %d %b %Y %H:%M:%S',
            time.localtime(new_expiration_date)
        )
        app.logger.error((
            'Error in updating user\'s expiration time in the db:\n'
            'session: {}\n'
            'DB expires_in: {}\n'
            'new_expiration_date: {}'
        ).format(session, readable_expires_in, readable_new_expiration))
        return {
            'access_token': None,
            'expiration_date': None
        }

    return {
        'access_token': api_key,
        'expiration_date': new_expiration_date
    }


# Web Views / Routes
@app.route('/index', methods=['GET'])
@lti(error=error, request='session', role='staff', app=app)
def index(course_id=None, user_id=None, lti=lti):
    # Cool, we got through
    args = request.args.to_dict()
    session['course_id'] = args['course_id']
    session['user_id'] = args['user_id']
    msg = "hi! Course ID is {}, User ID is {}.".format(session['course_id'], session['user_id'])

    return render_template('index.htm.j2', msg=msg)


# OAuth login
# Redirect URI
@app.route('/oauthlogin', methods=['POST', 'GET'])
@lti(error=error, role='staff', app=app)
@check_valid_user
def oauth_login(lti=lti):
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
        app.logger.error(
            '''Status code 500 from oauth, authentication error\n
            User ID: None Course: None \n {0} \n Request headers: {1} \n Session: {2}'''.format(
                r.url, r.headers, session
            )
        )

        msg = '''Authentication error,
            please refresh and try again. If this error persists,
            please contact support.'''
        return return_error(msg)

    elif r.status_code == 422:
        # https://github.com/instructure/canvas-lms/issues/1343
        app.logger.error(
            "Status code 422 from oauth, are your oauth scopes valid?"
        )

        msg = '''Authentication error,
            please refresh and try again. If this error persists,
            please contact support.'''
        return return_error(msg)


    if 'access_token' in r.json():
        session['api_key'] = r.json()['access_token']

        if 'refresh_token' in r.json():
            session['refresh_token'] = r.json()['refresh_token']

        if 'expires_in' in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = int(time.time())
            expires_in = current_time + r.json()['expires_in']
            session['expires_in'] = expires_in

            # check if user is in the db
            user = Users.query.filter_by(user_id=int(session['canvas_user_id'])).first()
            if user is not None:
                # update the current user's expiration time in db
                user.refresh_key = session['refresh_token']
                user.expires_in = session['expires_in']
                db.session.add(user)
                db.session.commit()

                # check that the expires_in time got updated
                check_expiration = Users.query.filter_by(user_id=int(session['canvas_user_id']))

                # compare what was saved to the old session
                # if it didn't update, error
                if check_expiration.expires_in == long(session['expires_in']):
                    course_id = session['course_id']
                    user_id = session['canvas_user_id']
                    return redirect(url_for('index', course_id=course_id, user_id=user_id))
                else:
                    app.logger.error(
                        '''Error in updating user's expiration time
                        in the db:\n {0}'''.format(session))
                    return return_error('''Authentication error,
                            please refresh and try again. If this error persists,
                            please contact support.''')
            else:
                # add new user to db
                new_user = Users(
                    session['canvas_user_id'],
                    session['refresh_token'],
                    session['expires_in']
                )
                db.session.add(new_user)
                db.session.commit()

                # check that the user got added
                check_user = Users.query.filter_by(user_id=int(session['canvas_user_id'])).first()

                if check_user is None:
                    # Error in adding user to the DB
                    app.logger.error(
                        "Error in adding user to db: \n {0}".format(session)
                    )
                    return return_error('''Authentication error,
                        please refresh and try again. If this error persists,
                        please contact support.''')
                else:
                    course_id = session['course_id']
                    user_id = session['canvas_user_id']
                    return redirect(url_for('index', course_id=course_id, user_id=user_id))

            # got beyond if/else
            # error in adding or updating db

            app.logger.error(
                "Error in adding or updating user to db: \n {0} ".format(session)
            )
            return return_error('''Authentication error,
                please refresh and try again. If this error persists,
                please contact support.''')

    app.logger.warning(
        "Some other error\n {0} \n {1} \n Request headers: {2} \n {3}".format(
            session, r.url, r.headers, r.json()
        )
    )
    msg = '''Authentication error,
        please refresh and try again. If this error persists,
        please contact support.'''
    return return_error(msg)


@app.route('/launch', methods=['POST', 'GET'])
@lti(error=error, request='initial', role='staff', app=app)
@check_valid_user
def launch(lti=lti):
    # Try to grab the user
    user = Users.query.filter_by(user_id=int(session['canvas_user_id'])).first()

    # Found a user
    if not user:
        # User not in database, go go OAuth!!
        app.logger.info(
            "Person doesn't have an entry in db, redirecting to oauth: {0}".format(session)
        )
        return redirect_to_auth()

    # Get the expiration date
    expiration_date = user.expires_in

    # If expired or no api_key
    if int(time.time()) > expiration_date or 'api_key' not in session:
        readable_time = time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime(user.expires_in))

        app.logger.info((
            'Expired refresh token or api_key not in session\n'
            'User: {0}\n'
            'Expiration date in db: {1}\n'
            'Readable expires_in: {2}'
        ).format(user.user_id, user.expires_in, readable_time))

        refresh = refresh_access_token(user)

        if refresh['access_token'] and refresh['expiration_date']:
            # Success! Set the API Key and Expiration Date
            session['api_key'] = refresh['access_token']
            session['expires_in'] = refresh['expiration_date']
            return redirect(url_for(
                'index',
                course_id=session['course_id'],
                user_id=session['canvas_user_id']
            ))
        else:
            # Refresh didn't work. Reauthenticate.
            app.logger.info('Reauthenticating:\nSession: {}'.format(session))
            return redirect_to_auth()
    else:
        # Have an API key that shouldn't be expired. Test it to be sure.
        auth_header = {'Authorization': 'Bearer ' + session['api_key']}
        r = requests.get(
            '{}users/{}/profile'.format(settings.API_URL, session['canvas_user_id']),
            headers=auth_header
        )

        # check for WWW-Authenticate
        # https://canvas.instructure.com/doc/api/file.oauth.html
        if 'WWW-Authenticate' not in r.headers and r.status_code != 401:
            return redirect(url_for(
                'index',
                course_id=session['course_id'],
                user_id=session['canvas_user_id']
            ))
        else:
            # Key is bad. First try to get a new one using refresh
            new_token = refresh_access_token(user)['access_token']

            if new_token:
                session['api_key'] = new_token
                return redirect(url_for(
                    'index',
                    course_id=session['course_id'],
                    user_id=session['canvas_user_id']
                ))
            else:
                # Refresh didn't work. Reauthenticate.
                app.logger.info('Reauthenticating:\nSession: {}'.format(session))
                return redirect_to_auth()


# XML
@app.route("/xml/", methods=['GET'])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    try:
        return Response(
            render_template('lti.xml.j2'),
            mimetype='application/xml'
        )
    except Exception:
        app.logger.error("No XML file.")
        msg = (
            'No XML file. Please refresh and try again. '
            'If this error persists, please contact support.'
        )
        return return_error(msg)
