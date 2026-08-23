const express = require('express');

const router = express.Router();

const {
    searchPlaces,
    getPlaceDetails,
    getRoute
} = require('../controller/mapController');


router.get('/places', searchPlaces);

router.get('/places/:placeId', getPlaceDetails);

router.post('/route', getRoute);


module.exports = router;