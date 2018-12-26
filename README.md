[![Join UCF Open Slack Discussions](https://ucf-open-slackin.herokuapp.com/badge.svg)](https://ucf-open-slackin.herokuapp.com/)

# Python
## Flask


### Virtual Environment
- Create a virtual environment and install from requirements.txt.

```
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

### Create settings.py from settings.py.template
- Update the API url and key
- Create the secret key, you can use the python shell:

```
import os
os.urandom(24)
```

##### Scope enforcement

You may optionally enable scope enforcement when you create your developer key for Canvas. This means that people using keys derived from your developer key will only be able to access the endpoints which are listed in the enforcement list, which is good for security.

To do this, turn on `Enforce Scopes` during the creation of your key. You can find the scopes you need beneath each API endpoint in the [Canvas API documentation](https://canvas.instructure.com/doc/api/index.html), listed after `Scope:`. The format listed is the exact format you'll need to use.

The base template requires that `url:GET|/api/v1/users/:user_id/profile` is checked. Your use of the Canvas API may require more.

Once you have enabled your desired scopes, place them in the configuration file in the list for `oauth2_scopes`, one per line.


### Create a DB
- Modify the model as you see fit before creating the db! SQLAlchemy can make migrating a pain.
- Here's how to use the example code:
- Change directory into the project folder. Create the database in python shell:
```
    from views import db
    db.create_all()
```
- If you want to look at your users table in the future, you can look at it in the python shell:
```
    from views import Users
    Users.query.all()
```

### Run
Here's how you run the flask app from the terminal:
```
export FLASK_APP=views.py
flask run
```

# Install LTI
- Have the XML, consumer key, and secret ready.
    - You can use the [XML Config Builder](https://www.edu-apps.org/build_xml.html) to build XML.
- Navigate to the course that you would like the LTI to be added to. Click Settings in the course navigation bar. Then, select the Apps tab. Near the tabs on the right side, click 'View App Configurations'. It should lead to a page that lists what LTIs are inside the course. Click the button near the tabs that reads '+ App'.
- A modal should come up that allows you to customize how the app gets added. Change the configuration in the Configuration Type dropdown menu to 'By URL' or 'Paste XML' depending on how you have your LTI configured. If your LTI is publicly accessible, 'By URL' is recommended. From there, fill out the Name and Consumer Keys, and the Config URL or XML Configuration. Click Submit.
- Your LTI will appear depending on specifications in the XML. Currently, they get specified in the **options** tag within the **extensions** tag. Extensions can include these options:
    - Editor Button (visible from within any wiki page editor in Canvas)
    - Homework Submission (when a student is submitting content for an assignment)
    - Course Navigation (link on the lefthand nav)
    - Account Navigation (account-level navigation)
    - User Navigation (user profile)

**Note**: If you're using Canvas, your version might be finicky about SSL certificates. Keep HTTP/HTTPS in mind when creating your XML and while developing your project. Some browsers will disable non-SSL LTI content until you enable it through clicking a shield in the browser bar or something similar.