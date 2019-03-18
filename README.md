[![Join UCF Open Slack Discussions](https://ucf-open-slackin.herokuapp.com/badge.svg)](https://ucf-open-slackin.herokuapp.com/)

# LTI Template: Flask with OAUTH tokens

## Set up a development server

### Virtual Environment
- Create a virtual environment and install from requirements.txt.

```
virtualenv env
source env/bin/activate
pip install -r requirements.txt
```

### Create developer key

Before running the testing server, you will need to create an OAUTH key and secret. On an Instructure-hosted Canvas instance, enter your Account Admin page and click `Developer Keys`. Click `+ Developer Key` to create a new key.

In the dialog that appears, give your key a name and set the owner email to your own email address. Enter `https://[my_server_url]/oauthlogin` as a redirect URI. Click "Save Key" when you are satisfied with all of the fields.

You will see your new key created in Canvas. Toggle its state from "Off" to "On" so your key is ready to use.


#### Scope enforcement

You may optionally enable scope enforcement when you create your developer key for Canvas. This means that people using keys derived from your developer key will only be able to access the endpoints which are listed in the enforcement list, which is good for security.

To do this, turn on `Enforce Scopes` during the creation of your key. You can find the scopes you need beneath each API endpoint in the [Canvas API documentation](https://canvas.instructure.com/doc/api/index.html), listed after `Scope:`. The format listed is the exact format you'll need to use for our settings file later.

The base template requires that `url:GET|/api/v1/users/:user_id/profile` is checked. Your use of the Canvas API may require more.


### Add server config

Copy `settings.py.template` to `settings.py` in this project's directory. Open it to configure the following options:

1. Set `BASE_URL` to the URL for your Canvas instance, for example `https://institution.instructure.com/`. Be sure to add the trailing slash!
1. Set `API_URL` to the URL for the API of your Canvas instance. In most cases, this is the same as `BASE_URL`. Be sure to add the trailing slash!
1. Set `LTI_CONSUMER_KEY` and `LTI_SHARED_SECRET` to any value you wish. Save this information for later, we'll use it while setting up the LTI.
1. Enter a random string in the `secret_key` field. This secret key is used to sign session cookies to prevent an attacker from tampering with their contents.
1. Set `oauth2_id` and `oauth2_key` to the ID and Key that Canvas gives you, respectively. The ID is shown under the "Details" column on the Developer Keys page. The key can be shown by clicking the "Show Key" button under the ID.
1. Set `oauth2_uri` to the redirect URI you entered for the developer key earlier.

You may also set `oauth2_scopes` if you wish. It takes a list of scope values, one for each API endpoint you will be using with the access tokens you gain. If you have scope enforcement enabled on your developer key, you **must** set `oauth2_scopes` to a list of endpoints less than or equal to those granted to your developer key.

If you are using [canvasapi](https://github.com/ucfopen/canvasapi), the endpoint used for each call is listed in [its class reference documentation](https://canvasapi.readthedocs.io/en/latest/canvas-ref.html). You may click on the endpoint listing to learn the `Scope:` value for the endpoint.


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

### Install LTI
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