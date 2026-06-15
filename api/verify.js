module.exports = async function handler(req, res) {
  // هذا الكود سيعيد ردًا بسيطًا جدًا ليخبرنا أن السيرفر يعمل
  res.status(200).json({ status: "Vercel is alive and connected!" });
};
