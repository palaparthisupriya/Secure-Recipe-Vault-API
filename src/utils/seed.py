"""
Database seeding script to initialize sample users with roles (admin, curator, user)
and sample recipes (public & private) for manual testing and demonstration.
"""
from src.database.session import SessionLocal, Base, engine
from src.models.user import User
from src.models.recipe import Recipe
from src.utils.hash import hash_password


def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Check if users already seeded
        existing_admin = db.query(User).filter(User.username == "admin").first()
        if existing_admin:
            print("[INFO] Database already contains seed data.")
            return

        print("[*] Seeding users...")
        users = [
            User(username="admin", password_hash=hash_password("Admin123!"), role="admin"),
            User(username="curator", password_hash=hash_password("Curator123!"), role="curator"),
            User(username="chef_alice", password_hash=hash_password("Alice123!"), role="user"),
            User(username="chef_bob", password_hash=hash_password("Bob12345!"), role="user"),
        ]
        db.add_all(users)
        db.commit()

        # Re-fetch users for foreign keys
        alice = db.query(User).filter(User.username == "chef_alice").first()
        bob = db.query(User).filter(User.username == "chef_bob").first()
        curator = db.query(User).filter(User.username == "curator").first()

        print("[*] Seeding initial recipes...")
        recipes = [
            Recipe(
                author_id=alice.id,
                title="Grandma's Secret Apple Pie",
                ingredients='["Apples", "Cinnamon", "Flour", "Butter", "Brown Sugar"]',
                instructions="Mix ingredients, bake at 375F for 45 minutes until golden.",
                is_public=False  # Private to Alice
            ),
            Recipe(
                author_id=alice.id,
                title="Classic Tomato Basil Soup",
                ingredients='["San Marzano Tomatoes", "Fresh Basil", "Garlic", "Heavy Cream", "Olive Oil"]',
                instructions="Simmer tomatoes and garlic, blend until smooth, stir in cream and basil.",
                is_public=True  # Public recipe
            ),
            Recipe(
                author_id=bob.id,
                title="Bob's Top-Secret BBQ Rub",
                ingredients='["Paprika", "Brown Sugar", "Cayenne Pepper", "Garlic Powder", "Sea Salt"]',
                instructions="Combine thoroughly in an airtight jar. Smoke brisket with hickory wood.",
                is_public=False  # Private to Bob
            ),
            Recipe(
                author_id=curator.id,
                title="Artisanal Sourdough Bread",
                ingredients='["Flour", "Water", "Wild Sourdough Starter", "Salt"]',
                instructions="Perform 4 stretch-and-folds, cold ferment for 24 hours, bake in Dutch oven.",
                is_public=True  # Public recipe
            )
        ]
        db.add_all(recipes)
        db.commit()
        print("[SUCCESS] Seeding complete! Seeded accounts:")
        print("  - admin / Admin123! (role: admin)")
        print("  - curator / Curator123! (role: curator)")
        print("  - chef_alice / Alice123! (role: user)")
        print("  - chef_bob / Bob12345! (role: user)")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
