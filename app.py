from flask import Flask, render_template, request, jsonify, send_from_directory
import folium
from folium.plugins import MarkerCluster, Draw, HeatMap
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
import json
from google.cloud import storage
from io import BytesIO

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///swarms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GCS_BUCKET_NAME'] = os.getenv('GCS_BUCKET_NAME', 'utba-swarmmap-media')

db = SQLAlchemy(app)

# Initialize Google Cloud Storage client
storage_client = storage.Client()
bucket = storage_client.bucket(app.config['GCS_BUCKET_NAME'])

# Database Models
class SwarmReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    media_files = db.relationship('MediaFile', backref='swarm_report', lazy=True)

class MediaFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    gcs_path = db.Column(db.String(255), nullable=False)
    swarm_report_id = db.Column(db.Integer, db.ForeignKey('swarm_report.id'), nullable=False)

def create_map():
    # Create a map centered on Toronto
    toronto_coords = [43.6532, -79.3832]
    m = folium.Map(
        location=toronto_coords,
        zoom_start=12,
        tiles='OpenStreetMap',
        control_scale=True
    )
    
    # Create a marker cluster for swarm reports
    swarm_cluster = MarkerCluster(name='Swarm Reports').add_to(m)
    
    # Add drawing tools
    draw = Draw(
        draw_options={
            'polyline': False,
            'polygon': False,
            'circle': False,
            'rectangle': False,
            'marker': True,
            'circlemarker': False
        },
        edit_options={'edit': True, 'remove': True}
    )
    draw.add_to(m)
    
    # Add geolocation control
    folium.plugins.LocateControl(
        position='topleft',
        strings={
            "title": "Show my location",
            "popup": "Your location"
        }
    ).add_to(m)
    
    # Add swarm reports to the map
    swarm_reports = SwarmReport.query.all()
    heat_data = []
    
    for report in swarm_reports:
        # Create popup content with media
        popup_content = f"""
            <div style='max-width: 300px;'>
                <p><strong>Reported:</strong> {report.timestamp.strftime('%Y-%m-%d %H:%M')}</p>
                <p><strong>Description:</strong> {report.description}</p>
                <div class='media-gallery'>
        """
        
        for media in report.media_files:
            # Generate signed URL for the media file (valid for 1 hour)
            blob = bucket.blob(media.gcs_path)
            signed_url = blob.generate_signed_url(
                version='v4',
                expiration=3600,  # 1 hour
                method='GET'
            )
            
            if media.file_type.startswith('image/'):
                popup_content += f"<img src='{signed_url}' style='max-width: 100%; margin: 5px;'>"
            elif media.file_type.startswith('video/'):
                popup_content += f"<video src='{signed_url}' controls style='max-width: 100%; margin: 5px;'></video>"
        
        popup_content += "</div></div>"
        
        # Add marker for the swarm report
        folium.Marker(
            location=[report.latitude, report.longitude],
            popup=folium.Popup(popup_content, max_width=300),
            icon=folium.Icon(color='orange', icon='bug'),
            tooltip=f"Swarm reported on {report.timestamp.strftime('%Y-%m-%d')}"
        ).add_to(swarm_cluster)
        
        # Add to heatmap data
        heat_data.append([report.latitude, report.longitude])
    
    # Add heatmap if there are reports
    if heat_data:
        HeatMap(heat_data, name='Swarm Heatmap').add_to(m)
    
    # Add layer control
    folium.LayerControl().add_to(m)
    
    # Add a minimap
    folium.plugins.MiniMap().add_to(m)
    
    # Add fullscreen option
    folium.plugins.Fullscreen().add_to(m)
    
    return m

@app.route('/')
def index():
    m = create_map()
    m.save('templates/map.html')
    return render_template('index.html')

@app.route('/report_swarm', methods=['POST'])
def report_swarm():
    try:
        data = request.form
        lat = float(data.get('latitude'))
        lng = float(data.get('longitude'))
        description = data.get('description', '')
        
        # Create new swarm report
        swarm_report = SwarmReport(
            latitude=lat,
            longitude=lng,
            description=description
        )
        db.session.add(swarm_report)
        db.session.flush()  # Get the ID of the new report
        
        # Handle file uploads
        files = request.files.getlist('media')
        for file in files:
            if file and file.filename:
                # Generate a unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = secure_filename(f"{timestamp}_{file.filename}")
                gcs_path = f"swarm_reports/{swarm_report.id}/{filename}"
                
                # Process image if it's an image file
                if file.content_type.startswith('image/'):
                    # Create a BytesIO object to hold the image data
                    img_data = BytesIO()
                    with Image.open(file) as img:
                        img.thumbnail((800, 800))
                        img.save(img_data, format=img.format, optimize=True, quality=85)
                    img_data.seek(0)
                    
                    # Upload to GCS
                    blob = bucket.blob(gcs_path)
                    blob.upload_from_file(img_data, content_type=file.content_type)
                else:
                    # Upload video directly
                    blob = bucket.blob(gcs_path)
                    blob.upload_from_file(file, content_type=file.content_type)
                
                # Create media file record
                media_file = MediaFile(
                    filename=filename,
                    file_type=file.content_type,
                    gcs_path=gcs_path,
                    swarm_report_id=swarm_report.id
                )
                db.session.add(media_file)
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Swarm report received',
            'data': {
                'id': swarm_report.id,
                'location': [lat, lng],
                'description': description,
                'timestamp': swarm_report.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 