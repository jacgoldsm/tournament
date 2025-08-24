from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import math

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tournament.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    points = db.Column(db.Integer,nullable=True)

class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default="Tournament")
    is_locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    seed = db.Column(db.Integer, nullable=False, unique=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    round_number = db.Column(db.Integer, nullable=False)  # 1-7
    match_number = db.Column(db.Integer, nullable=False)  # Position in round
    completed = db.Column(db.Boolean, nullable=False)
    player1_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)
    player2_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)

class UserPick(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    round_number = db.Column(db.Integer, nullable=False)  # 1-7
    player1_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)
    player2_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)
    picked_winner_id = db.Column(db.Integer, db.ForeignKey('player.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Helper Functions
def create_tournament_structure():
    """Create the tournament structure with 128 players and 7 rounds"""
    tournament = Tournament.query.first()
    if not tournament:
        tournament = Tournament(name="US Open 2025 Women's Draw")
        db.session.add(tournament)
        db.session.commit()
    
        # Clear existing matches
        Match.query.filter_by(tournament_id=tournament.id).delete()
        
        # Create matches for all 7 rounds
        total_matches = 127  # 64 + 32 + 16 + 8 + 4 + 2 + 1
        match_id = 1
        
        for round_num in range(1, 8):  # Rounds 1-7
            matches_in_round = 128 // (2 ** round_num)  # 64, 32, 16, 8, 4, 2, 1
            
            for match_num in range(1, matches_in_round + 1):
                match = Match(
                    tournament_id=tournament.id,
                    round_number=round_num,
                    match_number=match_num,
                    completed=False,
                )
                db.session.add(match)
    
    db.session.commit()
    return tournament

def get_or_create_admin():
    """Create admin user if it doesn't exist"""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='jacobg314@hotmail.com',
            password_hash=generate_password_hash('ll4misimo'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    return admin

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    tournament = Tournament.query.first()
    if not tournament:
        tournament = create_tournament_structure()

    if 'user_id' in session:
        initial_picks = UserPick.query.first()
        players = Player.query.first()
        if not initial_picks and players:
            all_matches = Match.query.order_by(Match.id).all()
            for match in all_matches:
                pick = UserPick(
                    tournament_id = match.tournament_id,
                    round_number = match.round_number,
                    match_id = match.id,
                    player1_id = match.player1_id,
                    player2_id = match.player2_id,
                    user_id = session['user_id'],
                )
                db.session.add(pick)
        db.session.commit()
    # Get all matches organized by round
    if 'user_id' in session:
        matches_by_round = {}
        for round_num in range(1, 8):
            matches_by_round[round_num] = UserPick.query.filter_by(
                tournament_id=tournament.id, 
                round_number=round_num
            ).order_by(UserPick.match_id).all()
    
    # Get user's picks
    user_picks = {}
    if 'user_id' in session:
        picks = UserPick.query.filter_by(user_id=session['user_id']).all()
        for pick in picks:
            user_picks[pick.match_id] = pick.picked_winner_id
    
    # Get all players
    players = {p.id: p for p in Player.query.all()}
    db.session.commit()
    
    return render_template('bracket.html', 
                         matches_by_round=matches_by_round,
                         user_picks=user_picks,
                         players=players,
                         tournament=tournament)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Admin access required')
        return redirect(url_for('index'))
    
    tournament = Tournament.query.first()
    players = Player.query.order_by(Player.seed).all()
    
    return render_template('admin.html', tournament=tournament, players=players)

@app.route('/admin/players', methods=['POST'])
def set_players():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    tournament = Tournament.query.first()
    if not tournament:
        tournament = create_tournament_structure()
    
    # Clear existing players
    Player.query.filter_by(tournament_id=tournament.id).delete()
    db.session.commit()  # Commit the deletion first
    
    # Add new players - handle both textarea input and list input
    player_names_raw = request.form.get('player_names', '')
    if player_names_raw:
        # Split by newlines for textarea input
        player_names = [name.strip() for name in player_names_raw.split('\n') if name.strip()]
    else:
        # Fallback to getlist for individual inputs
        player_names = request.form.getlist('player_names')
    
    # Ensure we have exactly 128 players
    player_names = player_names[:128]
    while len(player_names) < 128:
        player_names.append(f"Team {len(player_names) + 1}")
    
    # Add players to database
    for i, name in enumerate(player_names, 1):
        player = Player(
            name=name,
            seed=i,
            tournament_id=tournament.id
        )
        db.session.add(player)
    
    db.session.commit()  # Commit the players
    
    # Now get the players fresh from the database
    players_dict = {}
    players = Player.query.filter_by(tournament_id=tournament.id).all()
    for player in players:
        players_dict[player.seed] = player
    
    # Set up first round matches with players (64 matches)
    first_round_matches = Match.query.filter_by(
        tournament_id=tournament.id, 
        round_number=1
    ).order_by(Match.match_number).all()
    
    # Assign players to matches
    counter = 1
    for match in first_round_matches:
            seed1, seed2 = counter, counter + 1
            counter += 2
            player1 = players_dict.get(seed1)
            player2 = players_dict.get(seed2)
            
            if player1 and player2:
                match.player1_id = player1.id
                match.player2_id = player2.id
    
    db.session.commit()
    flash('Players set successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/lock_tournament', methods=['POST'])
def lock_tournament():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    tournament = Tournament.query.first()
    if tournament:
        tournament.is_locked = not tournament.is_locked
        db.session.commit()
        
        status = "locked" if tournament.is_locked else "unlocked"
        flash(f'Tournament {status} successfully!')
    
    return redirect(url_for('admin_panel'))

@app.route('/make_pick', methods=['POST'])
def make_pick():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    tournament = Tournament.query.first()
    if tournament and tournament.is_locked:
        return jsonify({'error': 'Tournament is locked'}), 403
    
    data = request.get_json()
    match_id = data.get('match_id')
    winner_id = data.get('winner_id')
    
    # Check if pick already exists
    existing_pick = UserPick.query.filter_by(
        user_id=session['user_id'],
        match_id=match_id
    ).first()
    
    existing_pick.picked_winner_id = winner_id
    existing_pick.updated_at = datetime.utcnow()


    current_match = Match.query.filter_by(id=match_id).first()
    next_obj = calculate_next_match(match_id, current_match.round_number)
    if current_match.round_number < 7:
        user_match = UserPick.query.filter_by(match_id=next_obj[0]).first()
        if next_obj[1] == 0:
            user_match.player1_id = winner_id
        else:
            user_match.player2_id = winner_id
    
    db.session.commit()
    return jsonify({'success': True})

def calculate_next_match(match_id, round_num):
    matches_in_round = 128 // (2 ** (round_num))  # 64, 32, 16, 8, 4, 2, 1
    matches_before_round = sum(128 // (2 **(num)) for num in range(1,round_num))
    match_within_round = match_id - matches_before_round
    val =  matches_before_round + matches_in_round
    struct = (
       val + ((match_within_round+1) // 2),
       (match_within_round + 1) % 2,
    )
    return struct
            

# Initialize database
@app.before_request
def create_tables():
    global initialized
    initialized = False
    if not initialized:
        db.create_all()
        get_or_create_admin()
        create_tournament_structure()
        initialized = True

if __name__ == '__main__':
    app.run(debug=True)