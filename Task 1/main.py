from flask import (
    Flask,
    session,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)
import botocore
import logging
import boto3
from boto3.session import Session
from boto3.dynamodb.conditions import Attr, And, Key
import requests
from concurrent.futures import ThreadPoolExecutor
import json
import os

# Because Dev on Windows, Prod on Linux.
import tempfile

app = Flask(__name__)
app.secret_key = "01234567"
app.logger.setLevel(logging.DEBUG)

DYNAMODB_LOGIN = "login"
DYNAMODB_SUBSCRIPTIONS = "subscriptions"
S3_BUCKET_NAME = "s3814655-task-1-bucket"
REGION_NAME = "ap-southeast-2"

# Public IP: http://13.236.86.181

# AWS sessions.
# Creds saved in AWS credentials file:
# DEV: C:\Users\AKYzX\.aws\credentials
# PROD: IAM role.

# For when on local.
# dynamodb_session = Session(profile_name="populate_login")
# s3_session = Session(profile_name="s3_read_write")

# For when on the EC2.
dynamodb_session = Session()
s3_session = Session()

# AWS Resources.
dynamodb_resource = dynamodb_session.resource("dynamodb", region_name=REGION_NAME)
s3_resource = s3_session.resource("s3", region_name=REGION_NAME)
login_table = dynamodb_resource.Table(DYNAMODB_LOGIN)
subscriptions_table = dynamodb_resource.Table(DYNAMODB_SUBSCRIPTIONS)
s3_bucket = s3_resource.Bucket(S3_BUCKET_NAME)
s3_client = s3_session.client("s3", region_name=REGION_NAME)


@app.route("/")
def root():
    if "email" in session:
        app.logger.info(f"User {session['username']} logged in. Redirecting to main.")
        return redirect(url_for("main"))
    else:
        app.logger.info("User not logged in. Redirecting to login page.")
        return redirect(url_for("login"))


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/login_submit", methods=["POST"])
def login_submit():
    error = None
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    # Validate form data.
    if not email:
        return render_template("register.html", error="Email is required.")
    elif "@" not in email:
        return render_template("register.html", error="Invalid email format.")
    elif not password:
        error = "Password is required."
    else:
        try:
            response = login_table.get_item(Key={"email": email})
            user = response.get("Item")

            # Set session.
            if user and user["password"] == password:
                session["username"] = user["user_name"]
                session["email"] = user["email"]
                return redirect(url_for("main"))
            else:
                error = "Email or password is invalid."
        except botocore.exceptions.ClientError as error_obj:
            error_code = error_obj.response["Error"]["Code"]
            app.logger.error(f"Received AWS DynamoDB error {error_code}: {error_obj}")
            error = "Login failed. Please try again."
        except Exception as e:
            app.logger.error(f"Error processing login: {e}")
            error = "Login failed. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    try:
        session.pop("email", None)
        session.pop("username", None)
        flash("Logged out.")
        return redirect(url_for("login"))
    except Exception as e:
        logging.error(f"Error during logout: {e}")
        return render_template(
            "login.html", error="An error occurred during logout. Please try again."
        )


@app.route("/register")
def register():
    app.logger.info("Accessed registration page.")
    return render_template("register.html")


@app.route("/register_submit", methods=["POST"])
def register_submit():
    try:
        app.logger.error("Entering.")

        # Verify form data.
        email = request.form.get("email", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Validate fields.
        if not email:
            app.logger.error("not email.")
            return render_template("register.html", error="Email is required.")
        elif "@" not in email:
            app.logger.error("not @.")
            return render_template("register.html", error="Invalid email format.")
        if not username:
            app.logger.error("not username.")
            return render_template("register.html", error="Username is required.")
        if not password:
            app.logger.error("not password.")
            return render_template("register.html", error="Password is required.")

        # Check if email already exists in DynamoDB 'login' table.
        response = login_table.get_item(Key={"email": email})
        user = response.get("Item")
        if user:
            flash("The email already exists.")
            return render_template("register.html")

        # Store in DynamoDB 'login' table.
        login_table.put_item(
            Item={
                "email": email,
                "user_name": username,
                "password": password,
            }
        )
        flash("Registration successful. You can now login.")
        return redirect(url_for("login"))
    except botocore.exceptions.ClientError as error:
        error_code = error.response["Error"]["Code"]
        error_message = error.response["Error"]["Message"]
        app.logger.error(f"Received AWS error {error_code}: {error_message}")
        flash("Registration failed. Please try again.")
        return render_template("register.html", error="Registration failed.")
    except Exception as e:
        app.logger.error(f"Error processing registration: {e}")
        return render_template("register.html", error="Not registered.")


@app.route("/main")
def main():
    # Fetch subscriptions from DynamoDB.
    email = session.get("email")
    subscriptions = get_subscriptions(email)
    return render_template(
        "main.html", user_name=session["username"], subscriptions=subscriptions
    )


def get_subscriptions(email):
    try:
        response = subscriptions_table.get_item(Key={"email": email})
        raw_subscriptions = response.get("Item", {}).get("subscriptions", [])

        subscriptions_with_images = []
        for sub in raw_subscriptions:
            title = sub.get("title")
            artist = sub.get("artist")

            # Fetch the image_url from the Music table using title and artist
            image_url = get_image_url_from_music_table(title, artist)

            # Convert the image URL to the S3 URL.
            s3_image_url = get_s3_image_url(image_url)
            sub["image_url"] = s3_image_url
            subscriptions_with_images.append(sub)
        return subscriptions_with_images
    except botocore.exceptions.ClientError as error:
        app.logger.error(f"Failed to fetch subscriptions for user {email}.")
        error_code = error.response["Error"]["Code"]
        app.logger.error(f"Received AWS DynamoDB error {error_code}: {error}")
        flash("Failed to import subscriptions.")
        return []


@app.route("/get-subscriptions", methods=["GET"])
def get_subscriptions_json():
    email = session.get("email")
    subscriptions = get_subscriptions(email)
    return jsonify(subscriptions=subscriptions)


def get_image_url_from_music_table(title, artist):
    try:
        music_table = dynamodb_resource.Table("music")
        response = music_table.get_item(Key={"title": title, "artist": artist})
        return response.get("Item", {}).get("image_url", "")
    except botocore.exceptions.ClientError as error:
        app.logger.error(
            f"Failed to fetch image_url for title: {title} and artist: {artist}."
        )
        error_code = error.response["Error"]["Code"]
        app.logger.error(f"Received AWS DynamoDB error {error_code}: {error}")
        return ""


def get_s3_image_url(image_url):
    filename = image_url.split("/")[-1]
    s3_key = f"artist_images/{filename}"
    s3_presigned_url = generate_presigned_url(S3_BUCKET_NAME, s3_key)
    return s3_presigned_url


def generate_presigned_url(bucket_name, object_name, expiration=3600):
    try:
        response = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": object_name},
            ExpiresIn=expiration,
        )
    except Exception as e:
        app.logger.error(f"Error generating pre-signed URL: {e}")
        return None
    return response


@app.route("/remove_subscription", methods=["POST"])
def remove_subscription():
    email = session.get("email")
    title = request.form.get("title")
    artist = request.form.get("artist")
    if not email or not title or not artist:
        return jsonify({"message": "Email, title or artist missing.", "success": False})

    # Get subscriptions.
    current_subscriptions = get_subscriptions(email)

    # Find the item to be removed.
    new_subscriptions = [
        music
        for music in current_subscriptions
        if not (music["title"] == title and music["artist"] == artist)
    ]

    # Update the subscriptions in the database.
    try:
        subscriptions_table.put_item(
            Item={"email": email, "subscriptions": new_subscriptions}
        )
        return jsonify(
            {"message": "Successfully removed subscription.", "success": True}
        )

    except botocore.exceptions.ClientError as error:
        app.logger.error(
            f"Failed to remove subscription for user {email} with title: {title}, and artist: {artist}."
        )
        error_code = error.response["Error"]["Code"]
        app.logger.error(f"Received AWS DynamoDB error {error_code}: {error}")
        flash("Failed to remove subscription.")
        return jsonify({"message": "Failed to remove subscription.", "success": False})


@app.route("/query_music", methods=["POST"])
def query_music():
    music_table = dynamodb_resource.Table("music")
    query_params = {
        "title": request.form.get("title"),
        "artist": request.form.get("artist"),
        "year": request.form.get("year"),
    }
    conditions = []
    expression_attribute_names = {}
    expression_attribute_values = {}
    for attr, value in query_params.items():
        if value:
            conditions.append(f"contains(#{attr}_attr, :{attr}_val)")
            expression_attribute_names[f"#{attr}_attr"] = attr
            expression_attribute_values[f":{attr}_val"] = value
    if not conditions:
        return jsonify({"message": "Query was empty.", "items": []})
    final_condition = " AND ".join(conditions)
    app.logger.debug(f"Final Condition: {final_condition}")
    app.logger.debug(f"Expression Attribute Names: {expression_attribute_names}")
    app.logger.debug(f"Expression Attribute Values: {expression_attribute_values}")
    response = music_table.scan(
        FilterExpression=final_condition,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
    )
    items = response.get("Items", [])
    results = []
    for item in items:
        image_filename = os.path.basename(item.get("image_url", ""))
        s3_key = f"artist_images/{image_filename}"
        signed_image_url = generate_presigned_url(S3_BUCKET_NAME, s3_key)
        results.append(
            {
                "title": item["title"],
                "year": item["year"],
                "artist": item["artist"],
                "image_url": signed_image_url,
            }
        )
    return jsonify(
        {
            "message": "Query successful." if results else "No results returned.",
            "items": results,
        }
    )


@app.route("/subscribe", methods=["POST"])
def subscribe():
    user_email = session["email"]
    music_table = dynamodb_resource.Table("music")
    title = request.form.get("title")
    artist = request.form.get("artist")
    try:
        # Get music details directly using title and artist.
        response = music_table.query(
            KeyConditionExpression=Key("title").eq(title) & Key("artist").eq(artist)
        )
        items = response.get("Items")
        if not items:
            return jsonify({"message": "Music item not found.", "success": False})
        music_item = items[0]

        # Check if already subscribed.
        existing_subscriptions = get_subscriptions(user_email)

        # Check if the music is already in subscriptions.
        if any(
            sub.get("title") == title and sub.get("artist") == artist
            for sub in existing_subscriptions
        ):
            return jsonify(
                {
                    "message": "You are already subscribed to this music item.",
                    "success": False,
                }
            )

        # Append the new music item to the existing subscriptions
        new_subscription = {
            "title": music_item["title"],
            "artist": music_item["artist"],
            "year": music_item["year"],
        }
        existing_subscriptions.append(new_subscription)

        # Update the subscriptions table
        subscriptions_table.update_item(
            Key={"email": user_email},
            UpdateExpression="SET subscriptions = :new_subscriptions",
            ExpressionAttributeValues={":new_subscriptions": existing_subscriptions},
        )
    except botocore.exceptions.ClientError as error:
        app.logger.error(
            f"Received AWS DynamoDB error {error.response['Error']['Code']}: {error}"
        )
        return jsonify({"message": "A DynamoDB error occurred.", "success": False})
    except Exception as e:
        app.logger.error(f"Error subscribing to music: {e}")
        return jsonify(
            {"message": "Error occurred while subscribing.", "success": False}
        )
    return jsonify({"message": "Subscribed successfully.", "success": True})


### UTILITIES ###

# @app.route("/")
# def test():
#     app.logger.info("Test.")
#     return "It worked!"


@app.route("/debug")
def debug_info():
    flask_env = app.config.get("ENV", "Not found in app.config")
    config_data = {key: str(value) for key, value in app.config.items()}
    config_output = "<br>".join(
        [f"{key}: {value}" for key, value in config_data.items()]
    )
    return f"Debug: {app.debug}<br>FLASK_ENV: {flask_env}<br><br>Complete Config:<br>{config_output}"


@app.route("/insert_users")
def insert_users():
    # Users data.
    users = [
        {
            "email": "s338146550@student.rmit.edu.au",
            "user_name": "Jesse Catchpole0",
            "password": "012345",
        },
        {
            "email": "s338146551@student.rmit.edu.au",
            "user_name": "Jesse Catchpole1",
            "password": "123456",
        },
        {
            "email": "s338146552@student.rmit.edu.au",
            "user_name": "Jesse Catchpole2",
            "password": "234567",
        },
        {
            "email": "s338146553@student.rmit.edu.au",
            "user_name": "Jesse Catchpole3",
            "password": "345678",
        },
        {
            "email": "s338146554@student.rmit.edu.au",
            "user_name": "Jesse Catchpole4",
            "password": "456789",
        },
        {
            "email": "s338146555@student.rmit.edu.au",
            "user_name": "Jesse Catchpole5",
            "password": "567890",
        },
        {
            "email": "s338146556@student.rmit.edu.au",
            "user_name": "Jesse Catchpole6",
            "password": "678901",
        },
        {
            "email": "s338146557@student.rmit.edu.au",
            "user_name": "Jesse Catchpole7",
            "password": "789012",
        },
        {
            "email": "s338146558@student.rmit.edu.au",
            "user_name": "Jesse Catchpole8",
            "password": "890123",
        },
        {
            "email": "s338146559@student.rmit.edu.au",
            "user_name": "Jesse Catchpole9",
            "password": "901234",
        },
    ]
    try:
        for user in users:
            app.logger.info(f"Inserting user with email: {user['email']}")
            login_table.put_item(Item=user)
            app.logger.info(f"Successfully inserted user with email: {user['email']}")
    except botocore.exceptions.ClientError as error:
        error_code = error.response["Error"]["Code"]
        error_message = error.response["Error"]["Message"]
        app.logger.error(f"Received AWS error {error_code}: {error_message}")
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return "Unexpected error."
    return "Users insertion completed!"


@app.route("/create_music_table")
def create_music_table():
    try:
        table = dynamodb_resource.create_table(
            TableName="music",
            KeySchema=[
                {"AttributeName": "title", "KeyType": "HASH"},
                {"AttributeName": "artist", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "title", "AttributeType": "S"},
                {"AttributeName": "artist", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table.wait_until_exists()
        app.logger.info(f"Table status: {table.table_status}")
        return "Music table created!"
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error creating table: {e}")
        return "Error creating table."
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return "Unexpected error."


@app.route("/populate_music_table")
def populate_music_table():
    try:
        with open("a2.json", "r") as file:
            music_data = json.load(file)
        music_table = dynamodb_resource.Table("music")

        # Add each 'song' to 'music' table.
        for song in music_data["songs"]:
            music_table.put_item(
                Item={
                    "title": song["title"],
                    "artist": song["artist"],
                    "year": song["year"],
                    "web_url": song["web_url"],
                    "image_url": song["img_url"],
                }
            )
        app.logger.info("Successfully populated the music table!")
        return "Successfully populated the music table!"
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error populating table: {e}")
        return "Error populating table."
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return "Unexpected error."


@app.route("/upload_music_image_to_s3")
def upload_music_image_to_s3():
    try:
        with open("a2.json", "r") as file:
            data = json.load(file)
            music_data = data["songs"]
    except Exception as e:
        app.logger.error(f"Failed to process JSON: {e}")
        return f"Error: {e}"

    # Extract image URLs.
    image_urls = [song.get("img_url") for song in music_data if song.get("img_url")]
    app.logger.info(f"List of image URLs: {image_urls}")

    # Parallel process images.
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(process_image_item, music_data)
    return "Music loading completed!"


def process_image_item(item):
    try:
        image_url = item.get("img_url")
        if image_url:
            app.logger.info(f"Processing image URL: {image_url}")

            # Save locally with the original filename.
            temp_dir = tempfile.gettempdir()
            local_filename = os.path.join(temp_dir, os.path.basename(image_url))
            download_image(image_url, local_filename)
            app.logger.info(f"Downloaded {image_url} to {local_filename}")

            # Upload to S3.
            s3_filename = f"artist_images/{os.path.basename(image_url)}"
            upload_to_s3(local_filename, s3_filename)
            app.logger.info(f"Uploaded {local_filename} to S3 as {s3_filename}")

            # Delete tmp file.
            os.remove(local_filename)
            app.logger.info(f"Deleted temporary file: {local_filename}")
        else:
            app.logger.warning(f"No image URL found for item: {item}")
    except botocore.exceptions.ClientError as error:
        error_code = error.response["Error"]["Code"]
        error_message = error.response["Error"]["Message"]
        app.logger.error(f"Received AWS error {error_code}: {error_message}")
    except Exception as e:
        app.logger.error(f"Error processing item {item}: {e}")


def download_image(url, local_filename):
    try:
        response = requests.get(url, stream=True)

        # Check the response status code.
        if response.status_code != 200:
            app.logger.error(
                f"Failed to download image from {url}. HTTP status code: {response.status_code}"
            )
            return None
        with open(local_filename, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)
        return local_filename
    except Exception as e:
        app.logger.error(f"Error downloading image from {url}: {e}")
        raise e


def upload_to_s3(local_filename, s3_filename):
    try:
        s3_bucket.upload_file(local_filename, s3_filename)
    except Exception as e:
        app.logger.error(f"Error uploading {local_filename} to S3: {e}")
        raise e


@app.route("/clear_bucket_and_temp")
def clear_bucket_and_temp():
    # Clear all images in 's3814655-task-1-bucket'.
    try:
        for obj in s3_bucket.objects.all():
            obj.delete()
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error deleting s3 object: {e}")
        return "Error deleting s3 object."
    app.logger.info("All S3 objects deleted.")

    # Delete images in the tmp directory, if they exist.
    temp_dir = tempfile.gettempdir()
    for filename in os.listdir(temp_dir):
        if filename.lower().endswith(".jpg"):
            file_path = os.path.join(temp_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
            except Exception as e:
                app.logger.error(f"Error deleting file {filename} from temp: {e}")
    app.logger.info("All tmp images deleted.")
    return "Bucket and temp directory cleared!"


@app.route("/delete_music_table")
def delete_music_table():
    try:
        table = dynamodb_resource.Table("music")
        table.delete()
        return "Music table deleted!"
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error deleting table: {e}")
        return "Error deleting table."


@app.route("/clear_music_table")
def clear_music_table():
    try:
        table = dynamodb_resource.Table("music")
        scan = table.scan()
        with table.batch_writer() as batch:
            for each in scan["Items"]:
                batch.delete_item(
                    Key={"title": each["title"], "artist": each["artist"]}
                )
        return "Music table cleared!"
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error clearing table: {e}")
        return "Error clearing table."


@app.route("/create_subscriptions_table")
def create_subscriptions_table():
    try:
        subscriptions_table_creation = dynamodb_resource.create_table(
            TableName=DYNAMODB_SUBSCRIPTIONS,
            KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "email", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        # Wait for table to be created.
        subscriptions_table_creation.wait_until_exists()
        app.logger.info(f"Table status: {subscriptions_table_creation.table_status}")
        return f"Table {DYNAMODB_SUBSCRIPTIONS} created successfully."
    except botocore.exceptions.ClientError as e:
        app.logger.error(f"Error creating table: {e}")
        return "Error creating table."
