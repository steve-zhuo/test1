from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_network.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    services = db.relationship('Service', backref='provider', lazy=True)
    reviews = db.relationship('Review', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text)
    website = db.Column(db.String(200))
    email = db.Column(db.String(120))
    owner_name = db.Column(db.String(100))
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviews = db.relationship('Review', backref='service', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    # Get stats from database
    total_service_providers = User.query.filter(User.services.any()).count()
    total_customers = Review.query.distinct(Review.author_id).count()
    total_reviews = Review.query.count()
    total_service_requests = Service.query.count()
    
    # Get recent services
    services = Service.query.order_by(Service.created_at.desc()).limit(10).all()
    
    return render_template('index.html', 
                         services=services,
                         total_service_providers=total_service_providers,
                         total_customers=total_customers,
                         total_reviews=total_reviews,
                         total_service_requests=total_service_requests)

@app.route('/services')
def services():
    query = request.args.get('q')
    category = request.args.get('category')
    
    if query:
        # First try to match the exact category name
        # Convert to lowercase and replace spaces with underscores
        category_name = query.lower().replace(' ', '_')
        services = Service.query.filter_by(category=category_name).all()
        
        # If no results, try to match partial category name
        if not services:
            services = Service.query.filter(Service.category.ilike(f'%{query}%')).all()
        
        # If still no results, try searching in title and description
        if not services:
            services = Service.query.filter(
                (Service.title.ilike(f'%{query}%')) |
                (Service.description.ilike(f'%{query}%'))
            ).all()
    elif category:
        # Filter by category
        services = Service.query.filter_by(category=category).all()
    else:
        # Show all services
        services = Service.query.all()
    
    return render_template('services.html', services=services)

@app.route('/filter_services')
def filter_services():
    category = request.args.get('category')
    if category:
        services = Service.query.filter_by(category=category).all()
    else:
        services = Service.query.all()
    
    service_html = ''
    for service in services:
        service_html += f'''
        <div class="col-md-4 mb-4">
            <div class="card h-100">
                <div class="card-body">
                    <h5 class="card-title">{service.title}</h5>
                    <p class="card-text">{service.description[:100]}...</p>
                    <p class="card-text"><small class="text-muted">Category: {service.category}</small></p>
                    <p class="card-text"><small class="text-muted">Posted by {service.provider.username}</small></p>
                    <a href="{url_for('service_detail', service_id=service.id)}" class="btn btn-primary">View Details</a>
                </div>
            </div>
        </div>
        '''
    
    return service_html  # Return only the service cards HTML, not the full template

@app.route('/services/<int:service_id>')
def service_detail(service_id):
    service = Service.query.get_or_404(service_id)
    # Load reviews with the service
    service.reviews = Review.query.filter_by(service_id=service_id).order_by(Review.created_at.desc()).all()
    print(f"Service ID: {service.id}")
    print(f"Number of reviews: {len(service.reviews)}")
    for review in service.reviews:
        print(f"Review: {review.content} by {review.author.username} - Rating: {review.rating}")
    return render_template('service_detail.html', service=service)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        phone_number = request.form['phone_number']
        owner_name = request.form.get('owner_name')
        email = request.form.get('email')
        address = request.form.get('address')
        website = request.form.get('website')
        review_content = request.form['review_content']
        review_rating = int(request.form['review_rating'])
        
        # Create service
        service = Service(
            title=title,
            description=description,
            category=category,
            phone_number=phone_number,
            owner_name=owner_name,
            email=email,
            address=address,
            website=website,
            provider_id=current_user.id
        )
        db.session.add(service)
        db.session.commit()
        
        # Create review
        review = Review(
            content=review_content,
            rating=review_rating,
            author_id=current_user.id,
            service_id=service.id
        )
        db.session.add(review)
        db.session.commit()
        
        return redirect(url_for('services', q=category))
    
    return render_template('add_service.html')

@app.route('/add_review/<int:service_id>', methods=['POST'])
@login_required
def add_review(service_id):
    service = Service.query.get_or_404(service_id)
    content = request.form.get('content')
    rating = int(request.form.get('rating'))
    
    review = Review(
        content=content,
        rating=rating,
        author_id=current_user.id,
        service_id=service_id
    )
    db.session.add(review)
    db.session.commit()
    
    flash('Review added successfully!')
    return redirect(url_for('service_detail', service_id=service_id))

@app.route('/contact_provider/<int:provider_id>', methods=['GET'])
@login_required
def contact_provider(provider_id):
    provider = User.query.get_or_404(provider_id)
    
    # For now, just redirect to the provider's services page
    # Later, we can implement a proper contact form
    return redirect(url_for('services', q=f'provider:{provider.username}'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return redirect(url_for('services', q=query))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
