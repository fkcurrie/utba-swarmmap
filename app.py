from flask import Flask, render_template
import folium

app = Flask(__name__)

@app.route('/')
def index():
    # Create a map centered on Toronto
    toronto_coords = [43.6532, -79.3832]
    m = folium.Map(location=toronto_coords, zoom_start=12)
    
    # Add a marker for Toronto City Hall
    folium.Marker(
        location=[43.6532, -79.3832],
        popup='Toronto City Hall',
        icon=folium.Icon(color='red', icon='info-sign')
    ).add_to(m)
    
    # Save the map to a template
    m.save('templates/map.html')
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) 