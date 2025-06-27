from app import db, User, Service
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

# Create sample users
users = [
    User(username="johndoe", email="john@example.com", password_hash="hashed_password"),
    User(username="janedoe", email="jane@example.com", password_hash="hashed_password"),
    User(username="mike", email="mike@example.com", password_hash="hashed_password"),
    User(username="sarah", email="sarah@example.com", password_hash="hashed_password")
]

# Add users to database
db.session.add_all(users)
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
        provider = random.choice(users)
        
        # Generate sample description
        description = f"Professional {title.lower()} offering top-quality services in your area. "
        description += "Fully licensed and insured. Quick response time and competitive pricing."
        
        # Create service
        service = Service(
            title=title,
            description=description,
            category=category,
            provider_id=provider.id,
            created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))  # Random creation date in last 30 days
        )
        
        db.session.add(service)

db.session.commit()

print("Database populated with sample data!")
