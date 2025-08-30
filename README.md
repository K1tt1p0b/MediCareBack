# MediCare - ระบบจัดการนัดหมายแพทย์

## โครงสร้างโปรเจค

```
ข้อสอบBackend_Frontend/
├── Backend/                 # Node.js + Express API
│   ├── MediCare_Api.js     # API Server
│   └── package.json
└── Frontend/               # Next.js Frontend
    └── medicare-frontend/
        ├── src/app/
        │   ├── (main)/     # หน้าหลัก (ต้องล็อกอิน)
        │   │   ├── admin/  # หน้า Admin Dashboard
        │   │   ├── appointment/
        │   │   ├── FindDoctor/
        │   │   └── profile/
        │   ├── admin-register/  # หน้าสร้าง Admin
        │   ├── login/
        │   └── register/
        └── src/app/api/    # Next.js API Routes
```

## การติดตั้งและใช้งาน

### 1. ติดตั้ง Backend



```bash
cd Backend
npm install
```

สร้างไฟล์ `.env`:
```env
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=medicare_db
JWT_SECRET=your_jwt_secret_key
PORT=3001
```

รัน Backend:
```bash
node MediCare_Api.js
```

### 2. ติดตั้ง Frontend

```bash
cd Frontend/medicare-frontend
npm install
```

รัน Frontend:
```bash
npm run dev
```

## ระบบความปลอดภัย

- **JWT Authentication:** ทุก API ต้องมี valid JWT token
- **Role-based Authorization:** Admin เท่านั้นที่เข้าถึง admin APIs ได้
- **Password Hashing:** รหัสผ่านถูกเข้ารหัสด้วย bcrypt
- **Input Validation:** ตรวจสอบข้อมูลที่รับเข้ามา

## การจัดการ Database

ระบบจะสร้างตารางต่อไปนี้โดยอัตโนมัติ:

- `users` - ข้อมูลผู้ใช้ทั้งหมด
- `doctors` - ข้อมูลหมอ (เชื่อมโยงกับ users)
- `time_slots` - ช่วงเวลาที่หมอว่าง
- `appointments` - การนัดหมาย



