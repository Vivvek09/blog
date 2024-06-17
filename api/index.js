const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const UserModel = require('./models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' })
const fs=require('fs');
const PostModel = require('./models/post');
const secret = "sejforfoenio";
const salt = bcrypt.genSaltSync(10);

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads',express.static(__dirname+'/uploads'))

mongoose.connect('mongodb+srv://vivekagangwani:attask1234@cluster0.ymdjq3t.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, salt);
    try {
        const userDoc = await UserModel.create({
            username,
            password: hashedPassword,
        });
        res.json(userDoc);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const userDoc = await UserModel.findOne({ username });

        if (!userDoc) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const isPasswordValid = bcrypt.compareSync(password, userDoc.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        jwt.sign({ id: userDoc._id }, secret, {}, (err, token) => {
            if (err) {
                return res.status(500).json({ message: 'Error generating token' });
            }

            res.cookie('token', token, { httpOnly: true }).json({
                id: userDoc._id,
                username: userDoc.username,
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/profile', async (req, res) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, secret);

        const user = await UserModel.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ id: user._id, username: user.username });
    } catch (err) {
        console.error('Error fetching profile:', err);

        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Unauthorized: Invalid token' });
        }

        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/logout',(req,res)=>{
    res.clearCookie('token').json('ok');

})

app.post('/post',uploadMiddleware.single('file'),async (req,res)=>{
    const {originalname,path}=req.file;
    const parts = originalname.split('.');
    const ext =parts[parts.length-1];
    const newPath=path+'.'+ext;
    fs.renameSync(path,newPath)
    
    const {token}=req.cookies;
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        const {title,summary,content} =req.body;
        const postDoc = await PostModel.create({
            title,
            summary,
            content,
            cover:newPath,
            author:info.id
        })
        res.json(postDoc);
    })
   
})


app.get('/post',async (req,res)=>{
    const posts = await PostModel.find()
    .populate('author')
    .sort({createdAt:-1})
    .limit(20)
    ;
    res.json(posts);
  })

  app.get('/post/:id',async(req,res)=>{
    const {id}=req.params;
    const post = await PostModel.findById(id).populate('author');
    res.json(post);
  })
  
 app.put('/post',uploadMiddleware.single('file'),async (req,res)=>{
    const {token}=req.cookies;
    let newPath=null;
    if(req.file){
        const {originalname,path}=req.file;
        const parts = originalname.split('.');
        const ext =parts[parts.length-1];
         newPath=path+'.'+ext
        fs.renameSync(path,newPath)
    }
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        
        const {id,title,summary,content} =req.body;
        const postDoc=await PostModel.findById(id)
        const isAuthor=JSON.stringify(postDoc.author)===JSON.stringify(info.id);
        if (!isAuthor){
            res.status(400).json('you are not the author');
            
        }
        postDoc.title = title;
            postDoc.summary = summary;
            postDoc.content = content;
            if (newPath) {
                postDoc.cover = newPath;
            }
            await postDoc.save();
            res.json(postDoc);

    })

 })

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});
