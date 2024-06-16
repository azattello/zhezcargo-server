const Router = require("express");
const User = require("../models/User") 
const bcrypt = require("bcryptjs")
const config = require("config")
const jwt = require("jsonwebtoken")
const {check, validationResult} = require("express-validator")
const authMiddleware = require('../middleware/auth.middleware')

const router = new Router()

// registration router
router.post('/registration', 
    [
        check('phone', 'Неверный номер телефона').not().isEmpty(),
        check('password', 'Неверный пароль').isLength({min: 4, max: 20}),
        check('name', 'Имя обязательно для заполнения').not().isEmpty(),
        check('surname', 'Фамилия обязательна для заполнения').not().isEmpty()
    ],
    async (req, res) => {
    try {
        console.log(req.body)

        const errors = validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({message: "Неверный запрос", errors})
        }

        const {phone, password, name, surname} = req.body;
        
        const candidate = await User.findOne({phone});
        
        if (candidate){
            return res.status(400).json({message: 'Пользователь с таким номером телефона уже существует'})
        }
        const hashPassword = await bcrypt.hash(password, 8)
        const user = new User({phone, password: hashPassword, name, surname, createdAt: new Date() })
        await user.save()
        return res.json({message: "Пользователь создан"})

    } catch (error) {
        console.log(error)
        res.send({message: "Server error"})
        
    }
})



// login router
router.post('/login', async (req, res) => {
    try {

        const {phone, password} = req.body
        const user = await User.findOne({phone})
        if (!user){
            return res.status(400).json({message: "Пользователь не найден"})
        }
        
        const isPassValid = bcrypt.compareSync(password, user.password)
        if(!isPassValid){
            return res.status(400).json({message: "Неверный пароль!"})
        }

        const token = jwt.sign({id: user.id}, config.get("secretKey"), {expiresIn: "30d"})
        return res.json({
            token,
            user: {
                id: user.id,
                phone: user.phone,
                name: user.name,
                surname: user.surname,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt
            }
        })

    } catch (error) {
        console.log(error)
        res.send({message: "Server error"})
        
    }
})


// auth router
router.get('/auth', authMiddleware, 
    async (req, res) => {
        try {
            const user = await User.findOne({_id: req.user.id})
            const token = jwt.sign({id: user.id}, config.get("secretKey"), {expiresIn: "30d"})
            return res.json({
                token,
                user: {
                    id: user.id,
                    phone: user.phone,
                    name: user.name,
                    surname: user.surname,
                    email: user.email,
                    role: user.role,
                    createdAt: user.createdAt
                }
            })

        } catch (error) {
            console.log(error)
            res.send({message: "Server error"})
            
        }
})


router.get('/profile', async (req, res) => {
    try {
        // Получаем токен из заголовка запроса или из cookies, где он может быть хранится
        const token = req.headers.authorization.split(' ')[1] || req.cookies.token;

        // Если токен не найден, отправляем ошибку
        if (!token) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        // Расшифровываем токен, чтобы получить идентификатор пользователя
        const decodedToken = jwt.verify(token, config.get('secretKey'));

        // Ищем пользователя в базе данных по идентификатору из токена
        const user = await User.findOne({ _id: decodedToken.id });

        // Если пользователь не найден, отправляем ошибку
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Возвращаем данные пользователя
        return res.json({
            user: {
                id: user.id,
                phone: user.phone,
                name: user.name,
                surname: user.surname,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    }
});


module.exports = router
