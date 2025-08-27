const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cors());

// Database Connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware for JWT Authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Middleware for Role-based Authorization
const authorizeRole = (role) => (req, res, next) => {
    if (req.user.role !== role) {
        return res.status(403).send('Forbidden. You do not have the required role.');
    }
    next();
};

// =================================================================
// 1. Authentication & User Management APIs
// =================================================================

// register (สำหรับการสมัครผู้ป่วยเท่านั้น)
app.post('/auth/register', async (req, res) => {
    const { username, password, fullName } = req.body;
    if (!username || !password || !fullName) {
        return res.status(400).send('Please provide all required fields.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const role = 'patient'; 
        
        await db.query(
            'INSERT INTO users (id, username, password_hash, full_name, role) VALUES (UUID(), ?, ?, ?, ?)',
            [username, hashedPassword, fullName, role]
        );
        res.status(201).send('User registered successfully as a patient.');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Username already exists.');
        }
        res.status(500).send('Internal Server Error');
    }
});

// login
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Please provide username and password.');
    }

    try {
        // แก้ไข SQL query ให้ดึง full_name มาด้วย
        const [rows] = await db.query('SELECT id, password_hash, role, full_name FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // ส่ง token และ object user ที่มี full_name กลับไป
        res.json({ 
            token,
            user: {
                id: user.id,
                full_name: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// get profile
app.get('/users/me', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT username, full_name, email, phone_number, address, role FROM users WHERE id = ?', [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).send('User not found.');
        }
        res.json(rows[0]);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// edit profile
app.put('/users/me', authenticateToken, async (req, res) => {
    const { full_name, email, phone_number, address } = req.body;
    
    // สร้าง Array สำหรับเก็บค่าที่จะอัปเดต
    const updates = {};
    if (full_name !== undefined) updates.full_name = full_name;
    if (email !== undefined) updates.email = email;
    if (phone_number !== undefined) updates.phone_number = phone_number;
    if (address !== undefined) updates.address = address;

    // ถ้าไม่มีข้อมูลที่จะอัปเดต
    if (Object.keys(updates).length === 0) {
        return res.status(400).send('No fields to update.');
    }

    // สร้าง SQL query แบบ dynamic
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);
    values.push(req.user.id);
    
    try {
        await db.query(
            `UPDATE users SET ${setClause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
            values
        );
        res.send('User profile updated successfully.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// =================================================================
// 2. Doctor Management APIs
// =================================================================

// GET /doctors?specialty={keyword}
app.get('/doctors', authenticateToken, async (req, res) => {
    const { specialty } = req.query;
    try {
        const [doctors] = await db.query(
            'SELECT d.id, u.full_name, d.specialty FROM doctors d JOIN users u ON d.user_id = u.id WHERE d.specialty LIKE ?',
            [`%${specialty}%`]
        );
        res.json(doctors);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// POST /doctors/:id/slots (Doctor only)
app.post('/doctors/:id/slots', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    const { id } = req.params;
    const { startTime, endTime } = req.body;
    if (req.user.id !== id) {
        return res.status(403).send('You can only manage your own slots.');
    }
    
    try {
        await db.query(
            'INSERT INTO time_slots (id, doctor_id, start_time, end_time) VALUES (UUID(), ?, ?, ?)',
            [id, startTime, endTime]
        );
        res.status(201).send('Time slot added successfully.');
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// GET /doctors/:id/slots
app.get('/doctors/:id/slots', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [slots] = await db.query(
            'SELECT start_time, end_time, is_booked FROM time_slots WHERE doctor_id = ? AND is_booked = FALSE',
            [id]
        );
        res.json(slots);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// =================================================================
// 3. Appointment Management APIs
// =================================================================

// POST /appointments (Patient only)
app.post('/appointments', authenticateToken, authorizeRole('patient'), async (req, res) => {
    const { doctorId, timeSlotId } = req.body;
    const patientId = req.user.id;

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        // Check if the time slot is still available
        const [slotRows] = await connection.query('SELECT * FROM time_slots WHERE id = ? AND is_booked = FALSE', [timeSlotId]);
        if (slotRows.length === 0) {
            await connection.rollback();
            return res.status(409).send('Time slot is not available.');
        }

        // Book the appointment and update the slot status
        await connection.query(
            'INSERT INTO appointments (id, patient_id, doctor_id, time_slot_id, status) VALUES (UUID(), ?, ?, ?, ?)',
            [patientId, doctorId, timeSlotId, 'booked']
        );
        await connection.query('UPDATE time_slots SET is_booked = TRUE WHERE id = ?', [timeSlotId]);

        await connection.commit();
        res.status(201).send('Appointment booked successfully.');
    } catch (error) {
        await connection.rollback();
        res.status(500).send('Internal Server Error');
    } finally {
        connection.release();
    }
});

// GET /appointments/me (Patient only)
app.get('/appointments/me', authenticateToken, authorizeRole('patient'), async (req, res) => {
    const patientId = req.user.id;
    try {
        const [appointments] = await db.query(
            'SELECT a.id, a.status, t.start_time, u.full_name AS doctor_name FROM appointments a JOIN time_slots t ON a.time_slot_id = t.id JOIN doctors d ON a.doctor_id = d.id JOIN users u ON d.user_id = u.id WHERE a.patient_id = ?',
            [patientId]
        );
        res.json(appointments);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// GET /appointments/doctor/me (Doctor only)
app.get('/appointments/doctor/me', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    const doctorId = req.user.id;
    try {
        const [appointments] = await db.query(
            'SELECT a.id, a.status, t.start_time, u.full_name AS patient_name FROM appointments a JOIN time_slots t ON a.time_slot_id = t.id JOIN users u ON a.patient_id = u.id WHERE a.doctor_id = ?',
            [doctorId]
        );
        res.json(appointments);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// =================================================================
// 4. Server Start
// =================================================================

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});