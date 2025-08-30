# MediCare - ระบบจัดการนัดหมายแพทย์


## ต้องใช้ Backend ด้วย
สามารถ Clone Project ตามลิงค์นี้ได้เลย https://github.com/K1tt1p0b/MediCareFront.git


## อย่าลืมติดตั้งฐานข้อมูล SQL ด้วย
DatabaseMediCare.sql


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

แนะนำให้ผู้ใช้คัดลอกข้อความที่คุณให้มาไปวางในไฟล์ .env ที่เพิ่งสร้างขึ้น และแก้ไขค่าของตัวแปรให้ตรงกับข้อมูลในเครื่องของตัวเองครับ

คำอธิบายตัวแปร:

DB_HOST: ที่อยู่ของฐานข้อมูล (ปกติจะเป็น localhost หรือ 127.0.0.1 ถ้าติดตั้งในเครื่องตัวเอง)

DB_USER: ชื่อผู้ใช้สำหรับฐานข้อมูล เช่น root

DB_PASSWORD: รหัสผ่านของฐานข้อมูล เช่น 1234

DB_NAME: ชื่อของฐานข้อมูลที่ต้องการใช้งาน เช่น DatabaseMediCare หรือ medicare

JWT_SECRET: คีย์ลับสำหรับสร้างและยืนยัน JSON Web Tokens เช่น asdfkohjg89345klj #สุ่มเปลี่ยนเอาได้ตามใจชอบ

PORT: หมายเลขพอร์ตที่เซิร์ฟเวอร์จะรัน เช่น 3001

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
- 
## รหัสของ Admin
kittipob.jir
123456


