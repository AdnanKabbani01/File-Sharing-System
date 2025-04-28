from database import Database

# Create an instance of the Database class
db = Database()

# Print all users
print("All users in the database:")
users = db.list_users()
for username, data in users.items():
    print(f"Username: {username}, Role: {data['role']}")

# Try to add a test user
test_username = "testuser"
test_password = "password123"
success = db.add_user(test_username, test_password)

if success:
    print(f"User {test_username} added successfully.")
else:
    print(f"Failed to add user {test_username}. User might already exist.")

# Test authentication with this user
success, role = db.authenticate_user(test_username, test_password)
if success:
    print(f"Authentication successful for {test_username}. Role: {role}")
else:
    print(f"Authentication failed for {test_username}")

# Test authentication with an existing user (admin)
admin_username = "admin"
admin_password = "admin123"
success, role = db.authenticate_user(admin_username, admin_password)
if success:
    print(f"Authentication successful for {admin_username}. Role: {role}")
else:
    print(f"Authentication failed for {admin_username}") 