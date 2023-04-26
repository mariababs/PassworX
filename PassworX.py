import os
import tkinter as tk
from tkinter import * 
import hashlib
import random
import smtplib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to show the startup screen widgets
def show_startup_screen():
    signInButton.place(x=90, y=250)
    newUserButton.place(x=260, y=250)

# Funtion to hide the startup screen widgets
def hide_startup_screen():
    signInButton.place_forget()
    newUserButton.place_forget()

# Function to show the sign in screen widgets
def show_signin_screen():
    signinBackButton.place(x=10, y=70)
    usernameLabel.place(x=100, y=200)
    usernameEntry.place(x=250, y=210)
    passwordLabel.place(x=100, y=250)
    passwordEntry.place(x=250, y=260)
    forgotButton.place(x=262, y=285)
    loginButton.place(x=180, y=350)

# Function to hide the sign in screen widgets
def hide_signin_screen():
    signinBackButton.place_forget()
    usernameLabel.place_forget()
    usernameEntry.place_forget()
    passwordLabel.place_forget()
    passwordEntry.place_forget()
    forgotButton.place_forget()
    loginButton.place_forget()
    notValidLabel.place_forget()
    usernameEntry.delete(0,'end')
    passwordEntry.delete(0,'end')

# Function to show the initial new user screen widgets (error labels not included)
def show_newuser_screen():
    newuserBackButton.place(x=10, y=70)
    usernameLabel_newuser.place(x=70, y=130)
    usernameEntry_newuser.place(x=205, y=140)
    passwordLabel_newuser.place(x=70, y=190)
    passwordEntry_newuser.place(x=205, y=200)
    confirmPasswordLabel_newuser.place(x=70, y=250)
    confirmPasswordEntry_newuser.place(x=300, y=260)
    emailLabel_newuser.place(x=70, y=310)
    emailEntry_newuser.place(x=265, y=320)
    submitButton.place(x=180, y=400)

# Function to hide all of the new user screen widgets
def hide_newuser_screen():
    newuserBackButton.place_forget()
    usernameLabel_newuser.place_forget()
    usernameEntry_newuser.place_forget()
    passwordLabel_newuser.place_forget()
    passwordEntry_newuser.place_forget()
    confirmPasswordLabel_newuser.place_forget()
    confirmPasswordEntry_newuser.place_forget()
    emailLabel_newuser.place_forget()
    emailEntry_newuser.place_forget()
    submitButton.place_forget()
    usernameErrorLabel.place_forget()
    passwordErrorLabel.place_forget()
    confirmErrorLabel.place_forget()
    emailErrorLabel.place_forget()

    # Clear the entries
    usernameEntry_newuser.delete(0, 'end')
    passwordEntry_newuser.delete(0, 'end')
    confirmPasswordEntry_newuser.delete(0, 'end')
    emailEntry_newuser.delete(0, 'end')

# Function to show logged in user screen
def show_loggedin_screen():
    # Place initial widgets
    loggedinBackButton.place(x=10, y=70)
    welcomeLabel.place(x=100, y=120)
    addnewButton.place(x=220, y=160)
    textbox.place(x=100, y=200)
    scrollbar.place(x=410, y=200, height=280)

    # Obtain hash of username from the welcome label
    user = welcomeLabel.cget("text")
    user = user[8:]
    hash_object_user = hashlib.sha256(user.encode())
    hex_dig_user = hash_object_user.hexdigest()
    # Generate the user's file name
    userFile = swap_characters(hex_dig_user)+".txt"

    # Clear the text box in case had previouse been filled
    textbox.configure(state='normal')
    textbox.delete('1.0', END)
    textbox.configure(state='disabled')

    # Decrypt the user's encrypted file
    decrypt_file(userFile+".enc",hex_dig_user[32:].encode())

    # open the text file
    f = open(userFile, 'r')
    # get the text from the file
    text = f.read()
    # set the disabled text box to the text from the file
    textbox.configure(state='normal')
    textbox.insert('1.0', text)
    textbox.configure(state='disabled')

    # close the file after use
    f.close()

# Function to hide widgets on the log in screen
def hide_loggedin_screen():
    loggedinBackButton.place_forget()
    welcomeLabel.place_forget()
    addnewButton.place_forget()
    textbox.place_forget()
    scrollbar.place_forget()

# Function to show initial widgets for the forgot password screen 
def show_forgot_screen():
    forgotBackButton.place(x=10, y=70)
    recoveryLabel.place(x=80,y=110)
    usernameLabel_forgot.place(x=70, y=140)
    usernameEntry_forgot.place(x=205, y=150)
    emailLabel_forgot.place(x=70, y=190)
    emailEntry_forgot.place(x=150, y=200)
    sendButton.place(x=180,y=430)

# Function to hide widgets on the forgot password screen
def hide_forgot_screen():
    forgotBackButton.place_forget()
    recoveryLabel.place_forget()
    usernameLabel_forgot.place_forget()
    usernameEntry_forgot.place_forget()
    emailLabel_forgot.place_forget()
    emailEntry_forgot.place_forget()
    codeLabel_forgot.place_forget()
    codeEntry_forgot.place_forget()
    passwordLabel_forgot.place_forget()
    passwordEntry_forgot.place_forget()
    confirmLabel_forgot.place_forget()
    confirmEntry_forgot.place_forget()
    sendButton.place_forget()
    submitCodeButton.place_forget()
    setButton.place_forget()
    usernameError_forgot.place_forget()
    emailError_forgot.place_forget()
    codeError_forgot.place_forget()
    passwordError_forgot.place_forget()
    confirmError_forgot.place_forget()
    
    # Clear entries of their current text
    usernameEntry_forgot.delete(0, 'end')
    emailEntry_forgot.delete(0, 'end')
    codeEntry_forgot.delete(0, 'end')
    passwordEntry_forgot.delete(0, 'end')
    confirmEntry_forgot.delete(0, 'end')

# Function for when sign in button is pressed
def sign_in_pressed():
    hide_startup_screen()
    show_signin_screen()

# Function for when new user button is pressed
def new_user_pressed():
    hide_startup_screen()
    show_newuser_screen()

# Function for when login button is pressed
def login_pressed():
    # Clear previous error message
    notValidLabel.place_forget()

    # Get Entries
    username = usernameEntry.get()
    password = passwordEntry.get()

    # Create hashes of username and password entries
    hash_object_username = hashlib.sha256(username.encode())
    hex_dig_username = hash_object_username.hexdigest()
    hash_object_password = hashlib.sha256(password.encode())
    hex_dig_password = hash_object_password.hexdigest()

    # Check if a users file even exists
    if os.path.exists("users.txt"):
        # Check if user name matches a user name in users file
        if find_username(hex_dig_username):
            # Check if password matches the user's password
            if find_password(hex_dig_password):
                # Username and password found and matched so display logged in screen
                welcomeString = "Welcome "+username
                welcomeLabel.configure(text=welcomeString)
                hide_signin_screen()
                show_loggedin_screen()
            else:
                # Not a valid password, display not valid credentials
                notValidLabel.place(x=200,y=170)
        else:
            # Not a valid username, valid credentials
            notValidLabel.place(x=200,y=170)
    else:
        # No users have been created so user does not exist
        notValidLabel.place(x=200,y=170)

# Function to find a username in the users file
def find_username(string):
    # Open the users file
    with open("users.txt") as f:
        lines = f.readlines()
        # Go through each line
        for i, line in enumerate(lines):
            # If on a username line and matches the provided username
            if i % 4 == 0 and line[:-1] == string:
                # Matches
                return True
        # None matched
        return False

# Function to find a password in the users file
def find_password(string):
    # Open the users file
    with open("users.txt") as f:
        lines = f.readlines()
        # Go through each line
        for i, line in enumerate(lines):
            # If on a username line and matches the provided password
            if i % 4 == 1 and line[:-1] == string:
                # Matches
                return True
        # None matched
        return False

# Function to find an email in the users file
def find_email(string):
    # Open the users file
    with open("users.txt") as f:
        # Go through each line
        lines = f.readlines()
        for i, line in enumerate(lines):
            # If on a username line and matches the provided email
            if i % 4 == 2 and line[:-1] == string:
                # Matches
                return True
        # None matched
        return False

# Function for when forgot password button is pressed
def forgot_pressed():
    # Display forgot password screen
    hide_signin_screen()
    show_forgot_screen()

# Function for when the back button on the sign in screen is pressed
def signin_back_pressed():
    # Display startup screen
    hide_signin_screen()
    show_startup_screen()

# Function for when the submit button on the new user screen is pressed
def submit_pressed():
    # hide previouse error messages
    usernameErrorLabel.place_forget()
    passwordErrorLabel.place_forget()
    confirmErrorLabel.place_forget()
    emailErrorLabel.place_forget()
    
    # Get text from entries
    username = usernameEntry_newuser.get()
    password = passwordEntry_newuser.get()
    confirmPassword = confirmPasswordEntry_newuser.get()
    email = emailEntry_newuser.get()

    # check username valid
    if check_username(username):
        # check if password is valid
        if check_password(password):
            # check confirm password matches password
            if password == confirmPassword:
                # check if email is valid (ish)
                if check_email(email):
                    # Good entries
                    # store hashes in users.txt
                    check_file("users.txt")
                    create_hash(username,password,email)
                    # Show startup screen so user can now sign in
                    hide_newuser_screen()
                    show_startup_screen()
                    # Clear entries
                    usernameEntry_newuser.delete(0, 'end')
                    passwordEntry_newuser.delete(0, 'end')
                    confirmPasswordEntry_newuser.delete(0, 'end')
                    emailEntry_newuser.delete(0, 'end')
                else:
                    # display email not valid
                    emailErrorLabel.place(x=310,y=340)
            else:
                # display passwords do not match
                confirmErrorLabel.place(x=310,y=280)
        else:
            # display passwrod error
            passwordErrorLabel.place(x=180,y=220)
    else:
        # display username error 
        usernameErrorLabel.place(x=200,y=160)

# Function to create hashes of new user credentials and store in in users file and create the user password file
def create_hash(user,pswd,eml):
    # Create hashes
    hash_object_user = hashlib.sha256(user.encode())
    hex_dig_user = hash_object_user.hexdigest()
    hash_object_pswd = hashlib.sha256(pswd.encode())
    hex_dig_pswd = hash_object_pswd.hexdigest()
    hash_object_eml = hashlib.sha256(eml.encode())
    hex_dig_eml = hash_object_eml.hexdigest()

    # Write the hases to the users file
    with open("users.txt", "a") as f:
        f.write(hex_dig_user)
        f.write("\n")
        f.write(hex_dig_pswd)
        f.write("\n")
        f.write(hex_dig_eml)
        f.write("\n\n")
    
    # Create the user's password file
    userFile = swap_characters(hex_dig_user)+".txt"
    open(userFile, "x")

    # Encrypt the user's password (should be empty at this point b/c user is new)
    encrypt_file(userFile,hex_dig_user[32:].encode())

# Function to check if a file exists
def check_file(filename):
    if not os.path.exists(filename):
        # File does not exist so create it
        open(filename, "w+")

# Function to check if user name is valid
def check_username(string):
    # Must be at least 5 characters and can't contain spaces
    if len(string) >= 5 and not " " in string:
        return True
    else:
        return False

# Function to check if a password is valid
def check_password(string):
    # Must be at least 8 characters, and have 1 uppercase, 1 lowercase, and 1 number.
    if len(string) >= 8 and any(char.isdigit() for char in string) and any(char.isupper() for char in string) and any(char.islower() for char in string):
        return True
    else:
        return False
  
# Function to check if an email is valid (ish)
def check_email(string):
    # Must have an @ symbol a . and at least one letter in between each
    if "@" in string and "." in string and len(string.split(".")[-1]) >= 3:
        return True
    else:
        return False

# Function for when back button on new user screen is pressed
def newuser_back_pressed():
    # Display start up screen
    hide_newuser_screen()
    show_startup_screen()

# Function for when logged in user screen back button is pressed, sign out button pressed
def loggedin_back_pressed():
    # sign out button pretty much

    # Retrieve name of user password file
    user = welcomeLabel.cget("text")
    user = user[8:]
    hash_object_user = hashlib.sha256(user.encode())
    hex_dig_user = hash_object_user.hexdigest()
    userFile = swap_characters(hex_dig_user)+".txt"

    # Encrypt user's password file
    encrypt_file(userFile,hex_dig_user[32:].encode())

    # Display the sign in screen
    hide_loggedin_screen()
    show_signin_screen()

# Function for when add new button on logged in user screen is pressed
def addnew_pressed():
    # hide text box and add new button
    addnewButton.place_forget()
    textbox.place_forget()
    scrollbar.place_forget()

    # show the 5 entries for title, date, username, password, email and their labels
    titleLabel_add.place(x=70,y=150)
    titleEntry_add.place(x=200,y=160)
    dateLabel_add.place(x=70,y=200)
    dateEntry_add.place(x=200,y=210)
    usernameLabel_add.place(x=70,y=250)
    usernameEntry_add.place(x=200,y=260)
    passwordLabel_add.place(x=70,y=300)
    passwordEntry_add.place(x=200,y=310)
    emailLabel_add.place(x=70,y=350)
    emailEntry_add.place(x=200,y=360)
    # Show the enter button
    enterButton.place(x=220,y=400)
    
# Function for when enter button is pressed
def enter_pressed():
    # Show the add new button and text box again
    addnewButton.place(x=220, y=160)
    textbox.place(x=100, y=200)
    scrollbar.place(x=410, y=200, height=280)
    
    # Hide all the entries, their labels, and the enter button
    titleLabel_add.place_forget()
    titleEntry_add.place_forget()
    dateLabel_add.place_forget()
    dateEntry_add.place_forget()
    usernameLabel_add.place_forget()
    usernameEntry_add.place_forget()
    passwordLabel_add.place_forget()
    passwordEntry_add.place_forget()
    emailLabel_add.place_forget()
    emailEntry_add.place_forget()
    enterButton.place_forget()

    # Grab the text from all the entries
    title = titleEntry_add.get()
    date = dateEntry_add.get()
    username = usernameEntry_add.get()
    password = passwordEntry_add.get()
    email = emailEntry_add.get()

    # Retriev name of user's password file
    user = welcomeLabel.cget("text")
    user = user[8:]
    hash_object_user = hashlib.sha256(user.encode())
    hex_dig_user = hash_object_user.hexdigest()
    userFile = swap_characters(hex_dig_user)+".txt"

    # Append data from entries to text file
    if os.path.exists(userFile):
        with open(userFile, "a") as f:
            f.write("Title:"+title+"\n")
            f.write("Date:"+date+"\n")
            f.write("Username:"+username+"\n")
            f.write("Password:"+password+"\n")
            f.write("Email:"+email+"\n")
            f.write("\n")
    else:
        # For some reason user's password file does not exist
        print("User password file does not exist")

    # Clear text box
    textbox.configure(state='normal')
    textbox.delete('1.0', END)
    textbox.configure(state='disabled')

    # open the text file
    f = open(userFile, 'r')
    # get the text from the file
    text = f.read()
    # set the disabled text box to the text from the file
    textbox.configure(state='normal')
    textbox.insert('1.0', text)
    textbox.configure(state='disabled')

    # close the file after use
    f.close()

    # clear entries
    titleEntry_add.delete(0, 'end')
    dateEntry_add.delete(0, 'end')
    usernameEntry_add.delete(0, 'end')
    passwordEntry_add.delete(0, 'end')
    emailEntry_add.delete(0, 'end')
    
# Function to swap every pair of characters in a in a string
def swap_characters(input): 
    result = "" 
    for i in range(0, len(input)-1, 2): 
        result += input[i+1] + input[i] 
    return result

# Function for when back button on the forgot password screen is pressed
def forgot_back_pressed():
    # Display sign in screen
    hide_forgot_screen()
    show_signin_screen()

# Function for when send button on forgot password screen is pressed
def send_pressed():
    # Variable for recovery code that gets generated
    global code

    # Hide any prior error labels
    usernameError_forgot.place_forget()
    emailError_forgot.place_forget()

    # Grab text from user name and email entries
    username = usernameEntry_forgot.get()
    email = emailEntry_forgot.get()

    # Generate hashes of username and email
    hash_object_username = hashlib.sha256(username.encode())
    hex_dig_username = hash_object_username.hexdigest()
    hash_object_email = hashlib.sha256(email.encode())
    hex_dig_email = hash_object_email.hexdigest()

    # Check that users file exist to see if possible that the user exists
    if os.path.exists("users.txt"):
        # Check that user name matches a username in file
        if find_username(hex_dig_username):
            # Check that email matches usernames email
            if find_email(hex_dig_email):
                # User exists 
                # generate 6 digit code
                code = generate_code()

                # send email of code
                send_email(email)
                print(code) # for debugging because google don't likey when lots of emails sent :(

                # display code label and entry
                codeLabel_forgot.place(x=70, y=240)
                codeEntry_forgot.place(x=280, y=250)

                # hide send button
                sendButton.place_forget()

                # display submit code button
                submitCodeButton.place(x=180,y=430)
            else: 
                # Email doesn't match
                emailError_forgot.place(x=150, y=220)
        else:
            # User doesn't exist
            usernameError_forgot.place(x=200, y=170)
    else:
        # User can't exist because none do
        usernameError_forgot.place(x=200, y=170)

def send_email(email_address):
    # Link to generate app password for the gmail
    # https://myaccount.google.com/u/1/apppasswords?pli=1&rapt=AEjHL4NBneYAZ1ewx5WsHr71X7rHrWo_a4n9XfxgTyDZyoavSKJoXGerQecI-nhvo-Qsn7mmETi6Gs_mLjm79NuKO0Q-gP3LRA

    # Data to send email: sender, receiever, and message
    sender_email = "passworx.recovery@gmail.com"
    receiver_email = email_address
    message = "Your Code is: "+str(code)+"."
    print(message) # For debugging

    # Access gmail smtp server
    server = smtplib.SMTP('smtp.gmail.com', 587)
    # Start TLS session
    server.starttls()
    # Login to passworx gmail
    server.login(sender_email, "wzcakmnunvrousqv")

    # Send email
    server.sendmail(sender_email, receiver_email, message)
    # End TLS session
    server.quit()

# Function to generate a random 6 digit code
def generate_code():
    digits = "0123456789"
    code = ""
    for i in range(6):
        code += random.choice(digits)
    return code

# Function for when submit code button on forgot password screen is pressed
def submitCode_pressed():
    # Hide code error label in case was placed previously
    codeError_forgot.place_forget()

    # Grab text from code entry
    codeEntered = codeEntry_forgot.get()
    
    # check if code entered is correct
    if codeEntered == code:
        # code is correct
        # diplay new password label and entry and display confirm label and entry
        passwordLabel_forgot.place(x=70, y=290)
        passwordEntry_forgot.place(x=260, y=300)
        confirmLabel_forgot.place(x=70, y=350)
        confirmEntry_forgot.place(x=300, y=360)

        # hide submit code button
        submitCodeButton.place_forget()

        # display set button
        setButton.place(x=180,y=430)
    else:
        # Code was not correct, display error
        codeError_forgot.place(x=280, y=270)

# Function for when set button on forgot password screen is pressed
def set_pressed():
    # Grab text from entries
    password = passwordEntry_forgot.get()
    confirm = confirmEntry_forgot.get()
    username = usernameEntry_forgot.get()

    # Check is password is a valid password
    if check_password(password):
        # Check is confirm entry matches password entry
        if password == confirm:
            # create hash of password and user name
            hash_object_password = hashlib.sha256(password.encode())
            hex_dig_password = hash_object_password.hexdigest()
            hash_object_username = hashlib.sha256(username.encode())
            hex_dig_username = hash_object_username.hexdigest()

            # replace that users password hash with the new one
            check_and_replace("users.txt",hex_dig_username,hex_dig_password)

            # hide the forgot screen
            hide_forgot_screen()

            # show the sign in screen
            show_signin_screen()
        else:
            # Confirm did not match password
            confirmError_forgot.place(x=300,y=380)
    else:
        # Password not a valid password
        passwordError_forgot.place(x=70, y=320)
    
# Function to find user in file and replace current password with new one
def check_and_replace(filename, user, newPass):
    # Open file
    with open(filename, 'r+') as f:
        lines = f.readlines()
        # Go through each line
        for i, line in enumerate(lines):
            # Find user
            if line.strip() == user:
                # Replace password with new password
                lines[i+1] = newPass + '\n'
        f.seek(0)
        f.writelines(lines) 

# Function to AES-OCB encrypt a file
def encrypt_file(file_name, key):
    # generate a random salt
    salt = get_random_bytes(8)
    # create a cipher using the key and the generated salt
    cipher = AES.new(key, AES.MODE_OCB, salt)
    # open the file to encrypt
    with open(file_name, 'rb') as f:
        # read the data from the file
        data = f.read()
    # encrypt the data
    enc_data = cipher.encrypt(data)
    # write the encrypted data to a file
    with open(file_name + ".enc", 'wb') as f:
        # write the salt at the beginning of the file
        f.write(salt)
        # write the encrypted data
        f.write(enc_data)

    # Remove the original not encrypted file
    os.remove(file_name)

# Function to decrypt a file that was AES-OCB encrypted
def decrypt_file(file_name, key):
    # open the encrypted file
    with open(file_name, 'rb') as f:
        # read the salt from the beginning of the file
        salt = f.read(8)
        # read the encrypted data
        enc_data = f.read()
    # create a cipher using the key and the salt
    cipher = AES.new(key, AES.MODE_OCB, salt)
    # decrypt the data
    data = cipher.decrypt(enc_data)
    # write the decrypted data to a file
    with open(file_name[:-4], 'wb') as f:
        f.write(data)
    
    # Remove original encrypted file
    os.remove(file_name)

# Function to execute when exit window button is pressed
def window_closed():
    # check if welcome label is currently on screen
    # if welcome label is on screen that means that user is logged in and their password file is currently decrypted
    if welcomeLabel.winfo_ismapped():
        # on log in screen
        print("On log in screen")
        
        # Retrieve name of user file
        user = welcomeLabel.cget("text")
        user = user[8:]
        hash_object_user = hashlib.sha256(user.encode())
        hex_dig_user = hash_object_user.hexdigest()
        userFile = swap_characters(hex_dig_user)+".txt"

        # Encrypt the user's password file
        encrypt_file(userFile,hex_dig_user[32:].encode())
    else:
        # not on log in screen
        pass

    # Close window
    root.destroy()
        
# Create window
root = tk.Tk()
root.geometry('500x500')
root.title('PassworX')

# Protocol to let function execute when window is suppossed to close
root.protocol("WM_DELETE_WINDOW", window_closed)

# Place logo at the top of the screen
image = tk.PhotoImage(file='Logo_Passworx.png')
label = tk.Label(root, image=image, width=300, height=50)
label.place(x=100, y=0)

# Widget creation for all the screens below:

# =============== STARTUP SCREEN ========================
signInButton = tk.Button(root, text='Sign In', width=10, height=4, font=('Arial Bold', 18), bg='blue', command=sign_in_pressed)
newUserButton = tk.Button(root, text='New User', width=10, height=4, font=('Arial Bold', 18), bg='red', command=new_user_pressed)
# =======================================================

# =============== SIGN IN SCREEN ========================
signinBackButton = tk.Button(root, text='< Back', width=8, height=1, font=('Arial Bold', 12), bg='black', fg='white', command=signin_back_pressed)
usernameLabel = tk.Label(root, text='Username:', font=('Arial Bold', 18))
usernameText = tk.StringVar()
usernameEntry = tk.Entry(root, width=22, textvariable=usernameText)
passwordLabel = tk.Label(root, text='Password:', font=('Arial Bold', 18))
passwordText = tk.StringVar()
passwordEntry = tk.Entry(root, width=22, textvariable=passwordText, show='*')
forgotButton = tk.Button(root, text='Forgot Password', width=14, height=1, font=('Arial Bold', 8), bg='gray', command=forgot_pressed)
loginButton = tk.Button(root, text='Login', width=10, height=2, font=('Arial Bold', 18), bg='purple', command=login_pressed)

# Error label
notValidLabel = tk.Label(root, text='Not valid credentials.', font=('Arial', 10), fg='red')
# =======================================================

# =============== NEW USER SCREEN ========================
newuserBackButton = tk.Button(root, text='< Back', width=8, height=1, font=('Arial Bold', 12), bg='black', fg='white', command=newuser_back_pressed)
usernameLabel_newuser = tk.Label(root, text='Username:', font=('Arial Bold', 18))
usernameText_newuser = tk.StringVar()
usernameEntry_newuser = tk.Entry(root, width=38, textvariable=usernameText_newuser)
passwordLabel_newuser = tk.Label(root, text='Password:', font=('Arial Bold', 18))
passwordText_newuser = tk.StringVar()
passwordEntry_newuser = tk.Entry(root, width=38, textvariable=passwordText_newuser, show='*')
confirmPasswordLabel_newuser = tk.Label(root, text='Confirm Password:', font=('Arial Bold', 18))
confirmPasswordText_newuser = tk.StringVar()
confirmPasswordEntry_newuser = tk.Entry(root, width=22, textvariable=confirmPasswordText_newuser, show='*')
emailLabel_newuser = tk.Label(root, text='Recovery Email:', font=('Arial Bold', 18))
emailText_newuser = tk.StringVar()
emailEntry_newuser = tk.Entry(root, width=28, textvariable=emailText_newuser)
submitButton = tk.Button(root, text='Submit', width=10, height=2, font=('Arial Bold', 18), bg='green', command=submit_pressed)

# Error labels
usernameErrorLabel = tk.Label(root, text='Must be at least 5 characters long. No spaces.', font=('Arial', 10), fg='red')
passwordErrorLabel = tk.Label(root, text='Must be at least 8 characters long with at least 1 \nuppercase, 1 lowercase, and 1 number.', font=('Arial', 10), fg='red')
confirmErrorLabel = tk.Label(root, text='Does not match.', font=('Arial', 10), fg='red')
emailErrorLabel = tk.Label(root, text='Not valid.', font=('Arial', 10), fg='red')
# =======================================================

# =============== LOGGED IN SCREEN ========================
loggedinBackButton = tk.Button(root, text='Sign Out', width=8, height=1, font=('Arial Bold', 12), bg='black', fg='white', command=loggedin_back_pressed)
welcomeLabel = tk.Label(root, text="Welcome", font=('Arial Bold', 18))
addnewButton = tk.Button(root, text='+ Add New', width=8, height=1, font=('Arial Bold', 12), bg='green', fg='white', command=addnew_pressed)
textbox = tk.Text(root, width=35, height=15, font=('Arial', 12), bg='white', fg='black', state='disabled')
scrollbar = tk.Scrollbar(root, orient='vertical')
scrollbar.config(command=textbox.yview, troughcolor='gray', width=15, activebackground='gray')

# Adding new entry subscreen widgets
titleLabel_add = tk.Label(root, text='Title:', font=('Arial Bold', 18))
titleText_add = tk.StringVar()
titleEntry_add = tk.Entry(root, width=38, textvariable=titleText_add)

dateLabel_add = tk.Label(root, text='Date:', font=('Arial Bold', 18))
dateText_add = tk.StringVar()
dateEntry_add = tk.Entry(root, width=38, textvariable=dateText_add)

usernameLabel_add = tk.Label(root, text='Username:', font=('Arial Bold', 18))
usernameText_add = tk.StringVar()
usernameEntry_add = tk.Entry(root, width=38, textvariable=usernameText_add)

passwordLabel_add = tk.Label(root, text='Password:', font=('Arial Bold', 18))
passwordText_add = tk.StringVar()
passwordEntry_add = tk.Entry(root, width=38, textvariable=passwordText_add)

emailLabel_add = tk.Label(root, text='Email:', font=('Arial Bold', 18))
emailText_add = tk.StringVar()
emailEntry_add = tk.Entry(root, width=38, textvariable=emailText_add)

enterButton = tk.Button(root, text='Enter', width=8, height=1, font=('Arial Bold', 18), bg='green', command=enter_pressed)

# =========================================================

# =============== FORGOT SCREEN ========================
forgotBackButton = tk.Button(root, text='< Back', width=8, height=1, font=('Arial Bold', 12), bg='black', fg='white', command=forgot_back_pressed)
recoveryLabel = tk.Label(root, text="Please enter username and email to reset password", font=('Arial', 12))
usernameLabel_forgot = tk.Label(root, text='Username:', font=('Arial Bold', 18))
usernameText_forgot = tk.StringVar()
usernameEntry_forgot = tk.Entry(root, width=38, textvariable=usernameText_forgot)
emailLabel_forgot = tk.Label(root, text='Email:', font=('Arial Bold', 18))
emailText_forgot = tk.StringVar()
emailEntry_forgot = tk.Entry(root, width=47, textvariable=emailText_forgot)
codeLabel_forgot = tk.Label(root, text='Code from email:', font=('Arial Bold', 18))
codeText_forgot = tk.StringVar()
codeEntry_forgot = tk.Entry(root, width=25, textvariable=codeText_forgot)
passwordLabel_forgot = tk.Label(root, text='New Password:', font=('Arial Bold', 18))
passwordText_forgot = tk.StringVar()
passwordEntry_forgot = tk.Entry(root, width=28, textvariable=passwordText_forgot, show='*')
confirmLabel_forgot = tk.Label(root, text='Confirm Password:', font=('Arial Bold', 18))
confirmText_forgot = tk.StringVar()
confirmEntry_forgot = tk.Entry(root, width=21, textvariable=confirmText_forgot, show='*')
sendButton = tk.Button(root, text='Send', width=8, height=1, font=('Arial Bold', 18), bg='green', command=send_pressed)
submitCodeButton = tk.Button(root, text='Submit', width=8, height=1, font=('Arial Bold', 18), bg='green', command=submitCode_pressed)
setButton = tk.Button(root, text='Set', width=8, height=1, font=('Arial Bold', 18), bg='green', command=set_pressed)

# Error labels
usernameError_forgot = tk.Label(root, text='User does not exist.', font=('Arial', 10), fg='red')
emailError_forgot = tk.Label(root, text='Email does not match user records.', font=('Arial', 10), fg='red')
codeError_forgot = tk.Label(root, text='Incorrect.', font=('Arial', 10), fg='red')
passwordError_forgot = tk.Label(root, text='Must be at least 8 characters long with at least 1 uppercase, \n1 lowercase, and 1 number.', font=('Arial', 10), fg='red')
confirmError_forgot = tk.Label(root, text='Does not match.', font=('Arial', 10), fg='red')

# =========================================================

# Show startup screen on startup
show_startup_screen()

# Event processing until window is closed
root.mainloop()
