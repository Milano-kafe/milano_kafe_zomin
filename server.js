const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB ulandi'))
  .catch(err => console.error('MongoDB ulanishda xatolik:', err));

const orderSchema = new mongoose.Schema({
    customer: String,
    phone: String,
    address: String,
    paymentMethod: String,
    items: [{
        id: Number,
        name: String,
        price: Number,
        image: String,
        quantity: Number
    }],
    total: Number,
    date: String,
    status: String
});

const Order = mongoose.model('Order', orderSchema);

const adminSchema = new mongoose.Schema({
    username: String,
    password: String
});

const Admin = mongoose.model('Admin', adminSchema);

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const admin = await Admin.findOne({ username });
        if (!admin) return res.status(401).json({ message: 'Noto\'g\'ri login yoki parol' });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(401).json({ message: 'Noto\'g\'ri login yoki parol' });

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server xatosi' });
    }
});

const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Autentifikatsiya talab qilinadi' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.adminId = decoded.id;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Noto\'g\'ri token' });
    }
};

app.post('/api/orders', async (req, res) => {
    try {
        const order = new Order(req.body);
        await order.save();
        res.status(201).json(order);
    } catch (error) {
        res.status(500).json({ message: 'Buyurtma saqlashda xatolik' });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Buyurtmalarni olishda xatolik' });
    }
});

app.patch('/api/orders/:id/complete', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { status: 'Bajarildi' }, { new: true });
        if (!order) return res.status(404).json({ message: 'Buyurtma topilmadi' });
        res.json(order);
    } catch (error) {
        res.status(500).json({ message: 'Buyurtma holatini o\'zgartirishda xatolik' });
    }
});

app.patch('/api/orders/:id/cancel', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { status: 'Bekor qilingan' }, { new: true });
        if (!order) return res.status(404).json({ message: 'Buyurtma topilmadi' });
        res.json(order);
    } catch (error) {
        res.status(500).json({ message: 'Buyurtma holatini o\'zgartirishda xatolik' });
    }
});

// Admin yaratish (bir marta ishlatish uchun)
const createAdmin = async () => {
    const username = 'admin';
    const password = 'admin123';
    try {
        const existingAdmin = await Admin.findOne({ username });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(password, 10);
            const admin = new Admin({ username, password: hashedPassword });
            await admin.save();
            console.log('Admin yaratildi:', { username, password });
        }
    } catch (error) {
        console.error('Admin yaratishda xatolik:', error);
    }
};
createAdmin();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server ${PORT} portida ishlamoqda`));