import streamlit as st
import warnings
warnings.filterwarnings("ignore")
import numpy as np
import pandas as pd
import joblib


#To Hide Warnings
st.set_option('deprecation.showfileUploaderEncoding', False)
st.set_option('deprecation.showPyplotGlobalUse', False)



df = pd.DataFrame(columns=["Date","User","IsVerified","Tweet"])
# Security
#passlib,hashlib,bcrypt,scrypt
import hashlib
def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password,hashed_text):
    if make_hashes(password) == hashed_text:
        return hashed_text
    return False
# DB Management
import sqlite3 
conn = sqlite3.connect('data.db')
c = conn.cursor()
# DB  Functions
def create_usertable():
    c.execute('CREATE TABLE IF NOT EXISTS userstable(username TEXT,password TEXT)')


def add_userdata(username,password):
    c.execute('INSERT INTO userstable(username,password) VALUES (?,?)',(username,password))
    conn.commit()

def login_user(username,password):
    c.execute('SELECT * FROM userstable WHERE username =? AND password = ?',(username,password))
    data = c.fetchall()
    return data


def view_all_users():
    c.execute('SELECT * FROM userstable')
    data = c.fetchall()
    return data


def main():
    st.title("Credit Card Fraud Detection")
    
 
    menu = ["Home","Login","SignUp"]
    choice = st.sidebar.selectbox("Menu",menu)
    
    

    if choice == "Home":
        st.markdown("It contains only numerical input variables which are the result of a PCA transformation. Unfortunately, due to confidentiality issues, we cannot provide the original features and more background information about the data. Features V1, V2, … V28 are the principal components obtained with PCA, the only features which have not been transformed with PCA are 'Time' and 'Amount'. Feature 'Time' contains the seconds elapsed between each transaction and the first transaction in the dataset. The feature 'Amount' is the transaction Amount, this feature can be used for example-dependant cost-sensitive learning. Feature 'Class' is the response variable and it takes value 1 in case of fraud and 0 otherwise.")
    
    
        

    elif choice == "Login":
        st.subheader("Enter Credentials")
        st.image("POINTING_LEFT.gif", width=100)
        st.write("(Please Enter Valid Credentials)")
        
        username = st.sidebar.text_input("User Name")
        password = st.sidebar.text_input("Password",type='password')
        if st.sidebar.checkbox("Login/Logout"):
            # if password == '12345':
            create_usertable()
            hashed_pswd = make_hashes(password)
            result = login_user(username,check_hashes(password,hashed_pswd))
            if result:
                st.success("Logged In as {}".format(username))
                st.sidebar.success("login Success.")
                menu2 = ["Single Analysis", "Analysis File"]
                choice = st.selectbox("Menu",menu2)
                if choice == "Single Analysis":
                    st.subheader("Single Analysis")
                    inputs = []
                    for i in range(1,29):
                        num = st.number_input(f"Enter Value of v{i}")
                        inputs.append(num)
                    amount = st.number_input(f"Enter Amount")
                    inputs.append(amount)
                    model = joblib.load("credit_card_model")
                    pred = model.predict([inputs])
                    if pred == 0:
                        st.subheader("Normal Transcation")
                    else:
                        st.subheader("Fraudulent Transcation")
                else :
                    st.subheader("Analysis File")
                    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
                    if uploaded_file is not None:
                        df = pd.read_csv(uploaded_file)
                        # create empty lists to store the predictions and the input data
                        predictions = []
                        input_data = []

                        # iterate over each row of the DataFrame
                        for index, row in df.iterrows():
                            # extract the values from the row as a list
                            input_values = row.tolist()
                            # pass the values to the predict function and append the result to the predictions list
                            model = joblib.load("credit_card_model")
                            
                            prediction = model.predict([input_values])
                            print(prediction)
                            if prediction[0] == 0:
                                predictions.append("Normal Transcation")
                            else:
                                predictions.append("Fraudulent Transcation")
                            # append the input data to the input_data list
                            input_data.append(input_values)
                        
                        # create a new DataFrame with the input data and the predictions
                        output_df = pd.DataFrame(input_data, columns=df.columns.tolist())
                        output_df['predictions'] = predictions

                        st.write(output_df)
                        
            else:
                st.warning("Incorrect Username/Password")




    elif choice == "SignUp":
        st.subheader("Create New Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password",type='password')

        if st.button("Signup"):
            create_usertable()
            add_userdata(new_user,make_hashes(new_password))
            st.success("You have successfully created a valid Account")
            st.info("Go to Login Menu to login")


if __name__ == '__main__':
	main()