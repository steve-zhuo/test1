from app import app, db, User, Service, Review
from datetime import datetime, timedelta
import random

# Sample data
categories = [
    "Food Services",
    "Auto Service",
    "Plumbing",
    "Electrical",
    "HVAC",
    "Roofing",
    "Gardening",
    "Home Improvement"
]

# Create admin user
with app.app_context():
    # Create admin user
    admin = User(username="admin", email="admin@example.com", created_at=datetime.utcnow() - timedelta(days=30))
    admin.set_password("SZ@pobconnect8256")
    db.session.add(admin)
    db.session.commit()

    # Create sample users
    providers = [
        User(username="provider1", email="provider1@example.com", password_hash="hashed_password", created_at=datetime.utcnow() - timedelta(days=30)),
        User(username="provider2", email="provider2@example.com", password_hash="hashed_password", created_at=datetime.utcnow() - timedelta(days=25)),
        User(username="provider3", email="provider3@example.com", password_hash="hashed_password", created_at=datetime.utcnow() - timedelta(days=20)),
        User(username="provider4", email="provider4@example.com", password_hash="hashed_password", created_at=datetime.utcnow() - timedelta(days=15))
    ]

    # Add providers to database
    db.session.add_all(providers)
    db.session.commit()

    # Create sample services for each category
    sample_services = {
        "Food Services": [
            "Best Local Catering Service",
            "Fresh Organic Produce Delivery",
            "Gourmet Restaurant Supplies",
            "Event Food Planning Expert"
        ],
        "Auto Service": [
            "24/7 Auto Repair Shop",
            "Mobile Oil Change Service",
            "Tire Replacement Specialists",
            "Auto Body Repair Shop"
        ],
        "Plumbing": [
            "Emergency Plumbing Services",
            "Water Heater Installation",
            "Drain Cleaning Experts",
            "Leak Detection Specialists"
        ],
        "Electrical": [
            "Licensed Electrician Services",
            "Home Wiring Experts",
            "Lighting Installation",
            "Circuit Breaker Repair"
        ],
        "HVAC": [
            "Heating & Cooling Repair",
            "Furnace Installation",
            "Air Conditioning Service",
            "Duct Cleaning Specialists"
        ],
        "Roofing": [
            "Professional Roof Repair",
            "Emergency Roof Leak Fix",
            "Gutter Installation",
            "Slate Roof Specialists"
        ],
        "Gardening": [
            "Lawn Care Services",
            "Tree Trimming Experts",
            "Landscaping Design",
            "Organic Gardening"
        ],
        "Home Improvement": [
            "Kitchen Remodeling",
            "Bathroom Renovation",
            "Floor Installation",
            "Painting Services"
        ]
    }

    # Create services
    for category, titles in sample_services.items():
        for title in titles:
            # Randomly select a user as provider
            provider = random.choice(providers)
            
            # Generate sample description
            description = f"Professional {title.lower()} offering top-quality services in your area. "
            description += "Fully licensed and insured. Quick response time and competitive pricing."
            
            # Generate additional details
            phone_number = f"(555) {random.randint(100, 999)}-{random.randint(1000, 9999)}"
            address = random.choice([
                "123 Main St",
                "456 Oak Ave",
                "789 Pine St",
                "321 Elm St",
                "654 Maple Ave"
            ])
            website = f"https://www.{title.lower().replace(' ', '-')}.com"
            email = f"info@{title.lower().replace(' ', '-')}.com"
            owner_name = random.choice(["John Smith", "Jane Doe", "Mike Johnson", "Sarah Wilson"])
            
            # Create service
            service = Service(
                title=title,
                description=description,
                category=category,
                phone_number=phone_number,
                address=address,
                website=website,
                email=email,
                owner_name=owner_name,
                provider_id=provider.id,
                created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
            )
            
            db.session.add(service)
            db.session.commit()

            # Create some reviews for each service
            for i in range(random.randint(3, 10)):
                review = Review(
                    content=random.choice([
                        "Excellent service! Highly recommend.",
                        "Great job, very professional.",
                        "Quick response and quality work.",
                        "Very satisfied with the service.",
                        "Would definitely use again."
                    ]),
                    rating=random.randint(1, 5),
                    author_id=random.choice(providers).id,
                    service_id=service.id,
                    created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                )
                db.session.add(review)
                db.session.commit()

print("Database populated with sample data!")
