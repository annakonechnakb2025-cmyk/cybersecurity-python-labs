from labs.lab02.task1 import Admin, User, UserAccount


def demo():
    print("=== User and UserAccount ===")

    user = User(
        "anna",
        "anna_13@example.com",
        "user",
    )

    user.set_password("Test123!")

    account = UserAccount(user)

    print("Login with correct password:")
    print(account.login("Test123!", "192.168.1.10"))

    print("Authenticated:")
    print(account.is_authenticated())

    print("Login with wrong password:")
    print(account.login("Wrong123!", "192.168.1.10"))

    print("\n=== Email validation ===")

    print("Current email:", user.email)

    user.email = "anna_new@example.com"
    print("New email:", user.email)

    try:
        user.email = "wrong-email"
    except ValueError as error:
        print("Invalid email:", error)

    print("\n=== Admin permissions ===")

    admin = Admin(
        "admin",
        "admin_13@example.com",
    )

    admin.grant_permission("read")
    admin.grant_permission("write")

    print(admin)
    print("Has read permission:", admin.has_permission("read"))
    print("Has delete permission:", admin.has_permission("delete"))

    admin.revoke_permission("write")

    print("After revoke:", admin)

    print("\n=== Logout ===")

    account.logout()
    print("Authenticated after logout:")
    print(account.is_authenticated())

    print("\n=== Audit Log ===")

    account.audit_log.show_all()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
