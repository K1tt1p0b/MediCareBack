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
// GET /users/me - ดึงข้อมูลโปรไฟล์ของผู้ใช้ (รวม bio และ license_number สำหรับหมอ)
app.get('/users/me', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // ใช้ LEFT JOIN เพื่อดึงข้อมูลจากตาราง doctors ด้วย
        const [rows] = await db.query(
            `SELECT
                u.username,
                u.full_name,
                u.email,
                u.phone_number,
                u.address,
                u.role,
                d.specialty,
                d.bio,
                d.license_number
            FROM users u
            LEFT JOIN doctors d ON u.id = d.user_id
            WHERE u.id = ?`,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /users/me - แก้ไขข้อมูล profile ของผู้ใช้ (รวมถึงข้อมูลแพทย์)
app.put('/users/me', authenticateToken, async (req, res) => {
    const { 
        full_name, 
        email, 
        phone_number, 
        address, 
        license_number, 
        bio 
    } = req.body;

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        const userId = req.user.id;
        
        // อัปเดตข้อมูลในตาราง users
        const userUpdates = {};
        const userValues = [];
        if (full_name !== undefined) {
            userUpdates.full_name = full_name;
            userValues.push(full_name);
        }
        if (email !== undefined) {
            userUpdates.email = email;
            userValues.push(email);
        }
        if (phone_number !== undefined) {
            userUpdates.phone_number = phone_number;
            userValues.push(phone_number);
        }
        if (address !== undefined) {
            userUpdates.address = address;
            userValues.push(address);
        }

        if (Object.keys(userUpdates).length > 0) {
            const userSetClause = Object.keys(userUpdates).map(key => `${key} = ?`).join(', ');
            userValues.push(userId);
            await connection.query(
                `UPDATE users SET ${userSetClause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                userValues
            );
        }

        // ถ้าผู้ใช้มี role เป็น 'doctor' ให้อัปเดตข้อมูลในตาราง doctors ด้วย
        const [userCheck] = await connection.query('SELECT role FROM users WHERE id = ?', [userId]);
        if (userCheck.length > 0 && userCheck[0].role === 'doctor') {
            const doctorUpdates = {};
            const doctorValues = [];
            if (license_number !== undefined) {
                doctorUpdates.license_number = license_number;
                doctorValues.push(license_number);
            }
            if (bio !== undefined) {
                doctorUpdates.bio = bio;
                doctorValues.push(bio);
            }

            if (Object.keys(doctorUpdates).length > 0) {
                const doctorSetClause = Object.keys(doctorUpdates).map(key => `${key} = ?`).join(', ');
                doctorValues.push(userId);
                await connection.query(
                    `UPDATE doctors SET ${doctorSetClause} WHERE user_id = ?`,
                    doctorValues
                );
            }
        }
        
        await connection.commit();
        res.send('User profile updated successfully.');

    } catch (error) {
        await connection.rollback();
        console.error('Error updating user profile:', error);
        res.status(500).send('Internal Server Error');
    } finally {
        connection.release();
    }
});

// change password
app.put('/users/me/password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).send('Please provide current password and new password.');
    }

    if (newPassword.length < 6) {
        return res.status(400).send('New password must be at least 6 characters long.');
    }

    try {
        // ตรวจสอบรหัสผ่านปัจจุบัน
        const [rows] = await db.query('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).send('User not found.');
        }

        const isValidPassword = await bcrypt.compare(currentPassword, rows[0].password_hash);
        if (!isValidPassword) {
            return res.status(401).send('Current password is incorrect.');
        }

        // เข้ารหัสรหัสผ่านใหม่
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        
        // อัปเดตรหัสผ่าน
        await db.query(
            'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [hashedNewPassword, req.user.id]
        );
        
        res.send('Password changed successfully.');
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

// GET /doctors/:id - ดึงข้อมูลแพทย์
app.get('/doctors/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // ดึงข้อมูลแพทย์จากตาราง doctors และ users
        const [doctors] = await db.query(`
            SELECT 
                d.id,
                d.specialty,
                d.license_number,
                d.bio,
                u.full_name,
                u.email,
                u.phone_number,
                u.address
            FROM doctors d
            JOIN users u ON d.user_id = u.id
            WHERE d.id = ?
        `, [id]);
        
        if (doctors.length === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        res.json(doctors[0]);
    } catch (error) {
        console.error('Error fetching doctor:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /doctors/:id/slots - ดึง time slots ของแพทย์
app.get('/doctors/:id/slots', async (req, res) => {
    try {
        const { id } = req.params;
        
        // ดึง time slots ของแพทย์
        const [timeSlots] = await db.query(`
            SELECT 
                id,
                start_time,
                end_time,
                is_booked,
                created_at
            FROM time_slots 
            WHERE doctor_id = ?
            ORDER BY start_time ASC
        `, [id]);
        
        res.json(timeSlots);
    } catch (error) {
        console.error('Error fetching time slots:', error);
        res.status(500).json({ error: 'Internal server error' });
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

// POST /appointments - จองนัดหมาย (Patient only)
app.post('/appointments', authenticateToken, authorizeRole('patient'), async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        const { doctor_id, time_slot_id, notes } = req.body;
        const patient_id = req.user.id;
        
        console.log('Creating appointment with data:', { doctor_id, time_slot_id, notes, patient_id });
        
        // ตรวจสอบว่า time slot ยังว่างอยู่หรือไม่
        const [timeSlotResult] = await connection.query(
            'SELECT * FROM time_slots WHERE id = ? AND doctor_id = ? AND is_booked = 0',
            [time_slot_id, doctor_id]
        );
        
        if (timeSlotResult.length === 0) {
            await connection.rollback();
            return res.status(409).json({ 
                error: 'Time slot is not available or already booked' 
            });
        }
        
        // ตรวจสอบว่า time slot ถูกจองไปแล้วหรือไม่
        const [existingAppointment] = await connection.query(
            'SELECT * FROM appointments WHERE time_slot_id = ?',
            [time_slot_id]
        );
        
        if (existingAppointment.length > 0) {
            await connection.rollback();
            return res.status(409).json({ 
                error: 'Time slot is already booked by another patient' 
            });
        }
        
        // สร้างการนัดหมาย
        const [appointmentResult] = await connection.query(
            'INSERT INTO appointments (id, patient_id, doctor_id, time_slot_id, notes, status) VALUES (UUID(), ?, ?, ?, ?, "booked")',
            [patient_id, doctor_id, time_slot_id, notes || '']
        );
        
        // อัปเดตสถานะ time slot เป็นไม่ว่าง
        await connection.query(
            'UPDATE time_slots SET is_booked = 1 WHERE id = ?',
            [time_slot_id]
        );
        
        await connection.commit();
        
        console.log('Appointment created successfully:', appointmentResult.insertId);
        
        res.status(201).json({ 
            id: appointmentResult.insertId, 
            message: 'Appointment created successfully' 
        });
        
    } catch (error) {
        await connection.rollback();
        console.error('Error creating appointment:', error);
        console.error('Error details:', {
            message: error.message,
            stack: error.stack,
            sqlMessage: error.sqlMessage
        });
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    } finally {
        connection.release();
    }
});

// GET /appointments/me (Patient only)
app.get('/appointments/me', authenticateToken, authorizeRole('patient'), async (req, res) => {
    const patientId = req.user.id;
    try {
        const [appointments] = await db.query(
            'SELECT a.id, a.status, t.start_time, u.full_name AS doctor_name, a.doctor_id FROM appointments a JOIN time_slots t ON a.time_slot_id = t.id JOIN doctors d ON a.doctor_id = d.id JOIN users u ON d.user_id = u.id WHERE a.patient_id = ? ORDER BY t.start_time ASC',
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
// 4. Admin Management APIs
// =================================================================

// POST /admin/register (สำหรับสร้าง admin user ครั้งแรก)
app.post('/admin/register', async (req, res) => {
    const { username, password, fullName } = req.body;
    if (!username || !password || !fullName) {
        return res.status(400).send('Please provide all required fields.');
    }

    try {
        // ตรวจสอบว่ามี admin อยู่แล้วหรือไม่
        const [existingAdmin] = await db.query('SELECT COUNT(*) as count FROM users WHERE role = "admin"');
        if (existingAdmin[0].count > 0) {
            return res.status(403).send('Admin user already exists. Cannot create another admin.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const role = 'admin';
        
        await db.query(
            'INSERT INTO users (id, username, password_hash, full_name, role) VALUES (UUID(), ?, ?, ?, ?)',
            [username, hashedPassword, fullName, role]
        );
        res.status(201).send('Admin user created successfully.');
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Username already exists.');
        }
        res.status(500).send('Internal Server Error');
    }
});

// GET /admin/users (Admin only) - ดึงรายการ users ทั้งหมด
app.get('/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const [users] = await db.query(
            `SELECT 
                u.id, 
                u.username, 
                u.full_name, 
                u.email, 
                u.phone_number, 
                u.address, 
                u.role, 
                d.specialty,
                u.created_at, 
                u.updated_at 
            FROM users u
            LEFT JOIN doctors d ON u.id = d.user_id
            ORDER BY u.created_at DESC`
        );
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
});

// POST /admin/users (Admin only) - สร้าง user ใหม่ (หมอหรือผู้ป่วย)
app.post('/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { username, password, fullName, role, specialty, email, phoneNumber, address } = req.body;
    
    if (!username || !password || !fullName || !role) {
        return res.status(400).send('Please provide all required fields.');
    }

    if (!['patient', 'doctor'].includes(role)) {
        return res.status(400).send('Role must be either "patient" or "doctor".');
    }

    if (role === 'doctor' && !specialty) {
        return res.status(400).send('Specialty is required for doctor role.');
    }

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // สร้าง user
        const [userResult] = await connection.query(
            'INSERT INTO users (id, username, password_hash, full_name, email, phone_number, address, role) VALUES (UUID(), ?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, fullName, email || null, phoneNumber || null, address || null, role]
        );
        
        // ดึง user ID ที่เพิ่งสร้าง
        const [newUser] = await connection.query('SELECT id FROM users WHERE username = ?', [username]);
        const userId = newUser[0].id;

        // ถ้าเป็นหมอ ให้สร้าง record ในตาราง doctors
        if (role === 'doctor') {
            await connection.query(
                'INSERT INTO doctors (id, user_id, specialty) VALUES (UUID(), ?, ?)',
                [userId, specialty]
            );
        }

        await connection.commit();
        res.status(201).send(`${role} user created successfully.`);
    } catch (error) {
        await connection.rollback();
        console.error('Error creating user:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send('Username already exists.');
        }
        res.status(500).send('Internal Server Error');
    } finally {
        connection.release();
    }
});

// PUT /admin/users/:id (Admin only) - แก้ไขข้อมูล user
app.put('/admin/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { id } = req.params;
    const { fullName, email, phoneNumber, address, role, specialty } = req.body;
    
    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        // อัปเดตข้อมูลในตาราง users
        await connection.query(
            'UPDATE users SET full_name = ?, email = ?, phone_number = ?, address = ?, role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [fullName, email, phoneNumber, address, role, id]
        );

        // ถ้าเปลี่ยน role เป็น doctor และยังไม่มีในตาราง doctors
        if (role === 'doctor') {
            const [existingDoctor] = await connection.query('SELECT id FROM doctors WHERE user_id = ?', [id]);
            if (existingDoctor.length === 0) {
                await connection.query(
                    'INSERT INTO doctors (id, user_id, specialty) VALUES (UUID(), ?, ?)',
                    [id, specialty]
                );
            } else if (specialty) {
                await connection.query('UPDATE doctors SET specialty = ? WHERE user_id = ?', [specialty, id]);
            }
        }

        // ถ้าเปลี่ยน role จาก doctor เป็นอย่างอื่น ให้ลบจากตาราง doctors
        if (role !== 'doctor') {
            await connection.query('DELETE FROM doctors WHERE user_id = ?', [id]);
        }

        await connection.commit();
        res.send('User updated successfully.');
    } catch (error) {
        await connection.rollback();
        res.status(500).send('Internal Server Error');
    } finally {
        connection.release();
    }
});

// DELETE /admin/users/:id (Admin only) - ลบ user
app.delete('/admin/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { id } = req.params;
    
    if (req.user.id === id) {
        return res.status(400).send('Cannot delete your own account.');
    }

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
        // ลบข้อมูลที่เกี่ยวข้องก่อน
        await connection.query('DELETE FROM appointments WHERE patient_id = ? OR doctor_id = ?', [id, id]);
        await connection.query('DELETE FROM time_slots WHERE doctor_id = ?', [id]);
        await connection.query('DELETE FROM doctors WHERE user_id = ?', [id]);
        await connection.query('DELETE FROM users WHERE id = ?', [id]);

        await connection.commit();
        res.send('User deleted successfully.');
    } catch (error) {
        await connection.rollback();
        res.status(500).send('Internal Server Error');
    } finally {
        connection.release();
    }
});

// GET /admin/doctors (Admin only) - ดึงรายการหมอทั้งหมด
app.get('/admin/doctors', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const [doctors] = await db.query(
            'SELECT d.id, u.id as user_id, u.username, u.full_name, u.email, u.phone_number, u.address, d.specialty, u.created_at, u.updated_at FROM doctors d JOIN users u ON d.user_id = u.id ORDER BY u.created_at DESC'
        );
        res.json(doctors);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});

// GET /admin/patients (Admin only) - ดึงรายการผู้ป่วยทั้งหมด
app.get('/admin/patients', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const [patients] = await db.query(
            'SELECT id, username, full_name, email, phone_number, address, created_at, updated_at FROM users WHERE role = "patient" ORDER BY created_at DESC'
        );
        res.json(patients);
    } catch (error) {
        res.status(500).send('Internal Server Error');
    }
});


// Doctor Management APIs
app.get('/doctors/me/appointments', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    try {
        const userId = req.user.id;
        console.log('User ID:', userId);
        
        // ดึง doctor_id จากตาราง doctors
        const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
        console.log('Doctor result:', doctorResult);
        
        if (doctorResult.length === 0) {
            console.log('Doctor not found for user:', userId);
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        const doctorId = doctorResult[0].id;
        console.log('Doctor ID:', doctorId);
        
        // ดึงนัดหมายของผู้ป่วยที่จองกับหมอคนนี้ (ใช้ status แทน is_booked)
        const [appointments] = await db.query(`
            SELECT 
                a.id,
                ts.start_time as appointment_datetime,
                a.notes,
                a.created_at as appointment_time,
                a.status,  -- เปลี่ยนจาก a.is_booked เป็น a.status
                a.created_at,
                u.full_name as patient_name,
                u.phone_number as patient_phone,
                u.email as patient_email,
                u.address as patient_address
            FROM appointments a
            JOIN users u ON a.patient_id = u.id
            JOIN time_slots ts ON a.time_slot_id = ts.id
            WHERE a.doctor_id = ? AND a.patient_id IS NOT NULL
            ORDER BY a.created_at ASC
        `, [doctorId]);
        
        console.log('Appointments found:', appointments.length);
        res.json(appointments);
    } catch (error) {
        console.error('Error fetching doctor appointments:', error);
        console.error('Error details:', {
            message: error.message,
            stack: error.stack,
            sqlMessage: error.sqlMessage
        });
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});


app.get('/doctors/me/time-slots', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    try {
        const userId = req.user.id;
        console.log('User ID:', userId);
        
        // ดึง doctor_id จากตาราง doctors
        const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
        console.log('Doctor result:', doctorResult);
        
        if (doctorResult.length === 0) {
            console.log('Doctor not found for user:', userId);
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        const doctorId = doctorResult[0].id;
        console.log('Doctor ID:', doctorId);
        
        // ดึง time slots ของหมอคนนี้ (ใช้ is_booked แทน is_available)
        const [timeSlots] = await db.query(`
            SELECT 
                ts.id,
                ts.start_time,
                ts.end_time,
                ts.is_booked,
                ts.created_at
            FROM time_slots ts
            WHERE ts.doctor_id = ? AND (ts.is_booked = 0 OR ts.is_booked IS NULL)
            ORDER BY ts.start_time ASC
        `, [doctorId]);
        
        console.log('Time slots found:', timeSlots.length);
        res.json(timeSlots);
    } catch (error) {
        console.error('Error fetching doctor time slots:', error);
        console.error('Error details:', {
            message: error.message,
            stack: error.stack,
            sqlMessage: error.sqlMessage
        });
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

app.post('/doctors/me/time-slots', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { start_time, end_time } = req.body;
        
        // ดึง doctor_id จากตาราง doctors
        const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
        if (doctorResult.length === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        const doctorId = doctorResult[0].id;
        
        // สร้าง time slot ใหม่ในตาราง time_slots (ใช้ is_booked = 0 = ว่าง)
        const [result] = await db.query(
            'INSERT INTO time_slots (id, doctor_id, start_time, end_time, is_booked) VALUES (UUID(), ?, ?, ?, 0)',
            [doctorId, start_time, end_time]
        );
        
        res.status(201).json({ 
            id: result.insertId, 
            message: 'Time slot created successfully' 
        });
    } catch (error) {
        console.error('Error creating time slot:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/doctors/me/time-slots/:id', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        const { start_time, end_time, is_booked } = req.body;
        
        // ดึง doctor_id จากตาราง doctors
        const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
        if (doctorResult.length === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        const doctorId = doctorResult[0].id;
        
        // อัปเดต time slot (เฉพาะของหมอคนนี้)
        const [result] = await db.query(
            'UPDATE time_slots SET start_time = ?, end_time = ?, is_booked = ? WHERE id = ? AND doctor_id = ?',
            [start_time, end_time, is_booked || 0, id, doctorId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Time slot not found or not authorized' });
        }
        
        res.json({ message: 'Time slot updated successfully' });
    } catch (error) {
        console.error('Error updating time slot:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/doctors/me/time-slots/:id', authenticateToken, authorizeRole('doctor'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;
        
        // ดึง doctor_id จากตาราง doctors
        const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [userId]);
        if (doctorResult.length === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        
        const doctorId = doctorResult[0].id;
        
        // ลบ time slot (เฉพาะของหมอคนนี้)
        const [result] = await db.query(
            'DELETE FROM time_slots WHERE id = ? AND doctor_id = ?',
            [id, doctorId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Time slot not found or not authorized' });
        }
        
        res.json({ message: 'Time slot deleted successfully' });
    } catch (error) {
        console.error('Error deleting time slot:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// =================================================================
// 5. Reports API
// =================================================================

// Helper middleware to authorize multiple roles (เพิ่มฟังก์ชันนี้เข้าไป)
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).send('Forbidden. You do not have the required role.');
        }
        next();
    };
};


// GET /reports/appointments?date=YYYY-MM-DD (admin/doctor) → ดูสรุปจำนวนการนัดหมาย
app.get('/reports/appointments', authenticateToken, authorizeRoles('admin', 'doctor'), async (req, res) => {
    // 1. ตรวจสอบ query parameter 'date'
    const { date } = req.query;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({ error: 'Invalid or missing date parameter. Please use YYYY-MM-DD format.' });
    }

    try {
        const { id, role } = req.user;

        // 2. สร้าง SQL query พื้นฐาน
        let query = `
            SELECT
                a.status,
                COUNT(*) AS count
            FROM
                appointments a
            JOIN
                time_slots ts ON a.time_slot_id = ts.id
            WHERE
                DATE(ts.start_time) = ?
        `;
        const queryParams = [date];

        // 3. ถ้าเป็น doctor ให้กรองข้อมูลเฉพาะของตัวเอง
        if (role === 'doctor') {
            // หา doctor_id จาก user_id
            const [doctorResult] = await db.query('SELECT id FROM doctors WHERE user_id = ?', [id]);
            if (doctorResult.length === 0) {
                return res.status(404).json({ error: 'Doctor profile not found for the current user.' });
            }
            const doctorId = doctorResult[0].id;

            query += ` AND a.doctor_id = ?`;
            queryParams.push(doctorId);
        }

        query += ` GROUP BY a.status`;

        // 4. ดึงข้อมูลจากฐานข้อมูล
        const [rows] = await db.query(query, queryParams);

        // 5. ประมวลผลและจัดรูปแบบข้อมูลเพื่อส่งกลับ
        const status_summary = {};
        let total_appointments = 0;

        rows.forEach(row => {
            status_summary[row.status] = row.count;
            total_appointments += row.count;
        });

        res.json({
            report_date: date,
            total_appointments,
            status_summary
        });

    } catch (error) {
        console.error('Error fetching appointment report:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// =================================================================
// 6. Server Start
// =================================================================

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});