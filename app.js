const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const cors = require('cors')

const app = express();
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: 'http://localhost:5050',
}));

const jwtSecret = "logiallTop";
const users = {
};

app.post("/user", (req, res, next) => {
  if (users[req.body.id]) {
    return res.status(401).json({ message: "이미 가입한 회원입니다." });
  } 
  users[req.body.id] = {
    id: req.body.id,
    password: req.body.password,
  };  
  return res.json({
    data: {
      id: req.body.id,
    },
  });
});

const verifyToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ message: "토큰이 없습니다." });
  }
  let decode;
  try {
    console.log(req.headers.authorization)
    decode = jwt.verify(
      req.headers.authorization.replace("Bearer ", ""),
      jwtSecret
    );
    res.locals.id = decode.id;
  } catch (error) {
   if (error.name === "TokenExpiredError") {
      return res
        .status(419)
        .json({ message: "만료된 액세스 토큰입니다.", code: "expired" });
    }
    return res
      .status(401)
      .json({ message: "유효하지 않은 액세스 토큰입니다." });  }
  next();
};

const verifyRefreshToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ message: "토큰이 없습니다." });
  }
  
  try {
    const data = jwt.verify(
      req.headers.authorization.replace("Bearer ", ""),
      jwtSecret
    );
    console.log("🚀 ~ file: app.js ~ line 71 ~ verifyRefreshToken ~ data", data)
    res.locals.id = data.id;

  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res
        .status(419)
        .json({ message: "만료된 리프레시 토큰입니다.", code: "expired" });
    }
    return res
      .status(401)
      .json({ message: "유효하지 않은 리프레시 토큰입니다." });
  }
  next();
};

app.get("/", (req, res) => {
  res.send("ok");
});

app.post("/refreshToken", verifyRefreshToken, (req, res, next) => {
  const accessToken = jwt.sign(
    { sub: "access", id: res.locals.id },
    jwtSecret,
    { expiresIn: "10m" }
  );
  console.log("🚀 ~ file: app.js ~ line 97 ~ app.post ~ accessToken", accessToken)

  if (!users[res.locals.id]) {
    return res.status(404).json({ message: "가입되지 않은 회원입니다." });
  }
  res.json({
    data: {
      accessToken,
      id: res.locals.id,
    },
  });
});


app.post("/login", (req, res, next) => {
  if (!users[req.body.id]) {
    return res.status(401).json({ message: "가입하지 않은 회원입니다." });
  }

  if (req.body.password !== users[req.body.id].password) {
    return res.status(401).json({ message: "잘못된 비밀번호입니다." });
  }

  const refreshToken = jwt.sign(
    { sub: "refresh", id: req.body.id },
    jwtSecret,
    { expiresIn: "1d" }
  );

  const accessToken = jwt.sign(
    { sub: "access", id: req.body.id },
    jwtSecret,
    { expiresIn: "10m" }
  );
  users[req.body.id].refreshToken = refreshToken;

  return res.json({
    data: {
      id: users[req.body.id].id,
      refreshToken,
      accessToken,
    },
  });
});

app.post("/logout", verifyToken, (req, res, next) => {
  delete users[res.locals.id];
  res.json({ message: "ok" });
});

app.get('/test',verifyToken, (req,res,next)=>{
  res.json({ message: "ok" });
})


app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json(err);
});

const server = app.listen(8090, () => {
  console.log("Server connecting..");
});

