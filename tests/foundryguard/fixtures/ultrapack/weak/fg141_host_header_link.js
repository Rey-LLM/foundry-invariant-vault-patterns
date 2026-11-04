async function forgotPassword(req, res) {
  const token = await createResetToken(req.body.email);
  const link = `https://${req.headers.host}/reset?token=${token}`;
  await sendMail(req.body.email, link);
  res.sendStatus(202);
}

module.exports = { forgotPassword };
