var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'backend-Test-2024'
app.use(express.json())
app.use(bodyParser.json());

app.use(cors())

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'mydb'
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization' ];
    const token = authHeader && authHeader.split(' ')[1];


    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.'  });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Failed to authenticate token.' });
        console.log('Decoded token',user)


        
        req.user = { userId: user.userId, email: user.email }; 
        next();
    });
    
}

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            'INSERT INTO users (email, password , fname , lname) VALUES (?,?,?,?)',
            [req.body.email, hash, req.body.fname, req.body.lname],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'ok', message: 'Register successfully' })
            }
        )
    });
})

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=? ',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    const accessToken = jwt.sign({  userId: users[0].userId,email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'ok', message: ' login success', accessToken: accessToken })
                } else {
                    res.json({ status: 'error', message: ' login failed' })
                }
            });
        }
    )
})
app.post('/authen', jsonParser, function (req, res, next) {
    try {
        var token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'ok', decoded });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
})


app.get('/profile', authenticateToken, (req, res) => {
    connection.execute(
        'SELECT userId, fname, lname, email, image FROM users WHERE email = ?',
        [req.user.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const user = {
                id: users[0].userId,
                fname: users[0].fname,
                lname: users[0].lname,
                email: users[0].email,
                image: users[0].image ? Buffer.from(users[0].image).toString('base64') : null

            };

            res.json({ status: 'ok', user });
        }
    );
});

app.get('/findAllBooking', (req, res) => {
    const sql = `
        SELECT 
            users.fname, 
            rooms.roomName
        FROM 
            bookings
        JOIN 
            users ON bookings.userId = users.userId
        JOIN 
            rooms ON bookings.roomId = rooms.roomId
        ORDER BY 
            users.fname;
    `;

    connection.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/bookingDetail', authenticateToken, (req, res) => {

    if (!req.user || !req.user.email) {
        return res.status(400).json({ status: 'error', message: 'User ID not found in token' });
    }
    connection.execute(`
            SELECT  
                bookings.bookingNumber,
                rooms.roomId AS NumberOfRooms,
                rooms.roomName,
                rooms.roomType,
                bookings.checkIn,
                bookings.checkOut,
                bookings.payment
            FROM 
                bookings
            JOIN 
                users ON bookings.userId = users.userId
            JOIN 
                rooms ON bookings.roomId = rooms.roomId
            WHERE 
                users.email = ?`,
                [req.user.email],
            function (err, results, fields) {
                if (err) { res.json({ status: 'error', message: err }); return }
                if (results.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

                const booking = results.map(result => ({
                    bookingNumber: result.bookingNumber,
                    NumberOfRooms: result.NumberOfRooms,
                    roomName: result.roomName,
                    roomType: result.roomType,
                    checkIn: result.checkIn,
                    checkOut: result.checkOut,
                    payment: result.payment
                }));
    
                res.json({ status: 'ok', booking });
            }
         )
})

const crypto = require('crypto');

function generateRandomBookingNumber(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const fixedPrefix = 'BBR';  
    let result = fixedPrefix;
 
    const remainingLength = length - fixedPrefix.length;
  
    for (let i = 0; i < remainingLength; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      result += charset[randomIndex];
    }
  
    return result;
  }


app.post('/booking', authenticateToken ,(req, res) => {
    const { roomId, checkIn, checkOut } = req.body;
    const userId = req.user.userId;
    const bookingNumber = generateRandomBookingNumber(8);

    const sql = 'INSERT INTO bookings (bookingNumber, userId, roomId, checkIn, checkOut) VALUES (?, ?, ?, ?, ?)';
    connection.query(sql, [ bookingNumber,userId, roomId, checkIn, checkOut], (err, result) => {
        if (!roomId || !checkIn || !checkOut) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        if (err) {
            console.error('Error inserting data:', err);
            res.status(500).json({ error: 'Failed to book room' });
        } else {
            res.status(200).json({ status: 'ok', message: 'Room booked successfully' });
        }
    });
});

app.post('/checkEmail', jsonParser, (req, res) => {
    const email = req.body.email;  // ใช้ req.body สำหรับ POST requests

    if (!email) {
        return res.status(400).json({ status: 'error', message: 'Email parameter is required.' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    connection.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ status: 'error', message: 'Database query failed.' });
        }
        
        if (results.length > 0) {
            return res.json({ exists: true });  // If email is found
        } else {
            return res.json({ exists: false });  // If email is not found
        }
    });
});


app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})