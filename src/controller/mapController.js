const axios = require('axios');

const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;

// Optional fallback country bias (Ghana) – used only if no user location is provided
const GHANA_BIAS = {
    rectangle: {
        low: { latitude: 4.5, longitude: -3.5 },
        high: { latitude: 11.5, longitude: 1.5 }
    }
};

/**
 * Search places using Google Places API – flexible, location-aware.
 * Query params:
 *   - query (required): search string
 *   - latitude (optional): user's current lat
 *   - longitude (optional): user's current lng
 *   - radius (optional): bias radius in meters (default: 50000 = 50km)
 *   - strictRegion (optional): if 'true', enforces Ghana-only results (rarely needed)
 */
exports.searchPlaces = async (req, res) => {
    try {
        const { query, latitude, longitude, radius, strictRegion } = req.query;

        if (!query || query.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Search query is required'
            });
        }

        const requestBody = {
            input: query,
            // No hardcoded region restriction by default – that's the flexibility!
        };

        // ----- FLEXIBLE BIAS -----
        if (latitude && longitude) {
            // Bias strongly toward the user's current location
            requestBody.locationBias = {
                circle: {
                    center: {
                        latitude: Number(latitude),
                        longitude: Number(longitude)
                    },
                    radius: Number(radius) || 50000 // default 50km, adjustable
                }
            };
        } else if (strictRegion === 'true') {
            // Only if explicitly asked, restrict to Ghana (rare)
            requestBody.locationRestriction = GHANA_BIAS;
        }
        // If no location and no strictRegion, Google returns global results (most flexible)

        const response = await axios.post(
            'https://places.googleapis.com/v1/places:autocomplete',
            requestBody,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Goog-Api-Key': GOOGLE_MAPS_API_KEY,
                    'X-Goog-FieldMask':
                        'suggestions.placePrediction.placeId,' +
                        'suggestions.placePrediction.text,' +
                        'suggestions.placePrediction.structuredFormat'
                }
            }
        );

        const suggestions = response.data.suggestions || [];

        const places = suggestions
            .filter(item => item.placePrediction)
            .map(item => {
                const prediction = item.placePrediction;
                return {
                    placeId: prediction.placeId,
                    name: prediction.structuredFormat?.mainText?.text ||
                        prediction.text?.text ||
                        '',
                    address: prediction.structuredFormat?.secondaryText?.text ||
                        ''
                };
            });

        return res.json({
            success: true,
            places
        });

    } catch (error) {
        console.error(
            'Google Places Error:',
            error.response?.data || error.message
        );

        return res.status(error.response?.status || 500).json({
            success: false,
            message: 'Place search failed',
            error: error.response?.data || error.message
        });
    }
};

/**
 * Get details for a selected place – no restrictions here, always flexible.
 */
exports.getPlaceDetails = async (req, res) => {
    try {
        const { placeId } = req.params;

        if (!placeId) {
            return res.status(400).json({
                success: false,
                message: 'Place ID is required'
            });
        }

        const response = await axios.get(
            `https://places.googleapis.com/v1/places/${placeId}`,
            {
                headers: {
                    'X-Goog-Api-Key': GOOGLE_MAPS_API_KEY,
                    'X-Goog-FieldMask':
                        'id,displayName,formattedAddress,location'
                }
            }
        );

        const place = response.data;

        return res.json({
            success: true,
            place: {
                placeId: place.id,
                name: place.displayName?.text || '',
                address: place.formattedAddress || '',
                latitude: place.location?.latitude,
                longitude: place.location?.longitude
            }
        });

    } catch (error) {
        console.error(
            'Place Details Error:',
            error.response?.data || error.message
        );

        return res.status(500).json({
            success: false,
            message: 'Place details failed',
            error: error.response?.data || error.message
        });
    }
};

/**
 * Calculate route – already flexible, no changes needed.
 */
exports.getRoute = async (req, res) => {
    try {
        const {
            originLatitude,
            originLongitude,
            destinationLatitude,
            destinationLongitude
        } = req.body;

        if (
            originLatitude === undefined ||
            originLongitude === undefined ||
            destinationLatitude === undefined ||
            destinationLongitude === undefined
        ) {
            return res.status(400).json({
                success: false,
                message: 'Origin and destination coordinates are required'
            });
        }

        const requestBody = {
            origin: {
                location: {
                    latLng: {
                        latitude: Number(originLatitude),
                        longitude: Number(originLongitude)
                    }
                }
            },
            destination: {
                location: {
                    latLng: {
                        latitude: Number(destinationLatitude),
                        longitude: Number(destinationLongitude)
                    }
                }
            },
            travelMode: 'DRIVE',
            routingPreference: 'TRAFFIC_AWARE',
            computeAlternativeRoutes: false,
            languageCode: 'en-US',
            units: 'METRIC'
        };

        const response = await axios.post(
            'https://routes.googleapis.com/directions/v2:computeRoutes',
            requestBody,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Goog-Api-Key': GOOGLE_MAPS_API_KEY,
                    'X-Goog-FieldMask':
                        'routes.duration,' +
                        'routes.distanceMeters,' +
                        'routes.polyline.encodedPolyline'
                }
            }
        );

        const route = response.data.routes?.[0];

        if (!route) {
            return res.status(404).json({
                success: false,
                message: 'No route found'
            });
        }

        const distanceKm = Number(route.distanceMeters || 0) / 1000;
        const durationSeconds = parseInt(
            String(route.duration || '0s').replace('s', ''),
            10
        );
        const durationMinutes = Math.ceil(durationSeconds / 60);

        return res.json({
            success: true,
            route: {
                distanceMeters: route.distanceMeters,
                distanceKm: Number(distanceKm.toFixed(2)),
                durationSeconds,
                durationMinutes,
                encodedPolyline: route.polyline?.encodedPolyline || ''
            }
        });

    } catch (error) {
        console.error(
            'Google Routes Error:',
            error.response?.data || error.message
        );

        return res.status(500).json({
            success: false,
            message: 'Route calculation failed',
            error: error.response?.data || error.message
        });
    }
};