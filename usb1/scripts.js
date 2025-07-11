function searchGame() {
  const query = document.getElementById('search').value.trim();
  if (query === "") {
    alert("يرجى إدخال اسم اللعبة للبحث.");
  } else {
    alert("تم البحث عن اللعبة: " + query);
    // مستقبلاً تربطها بقاعدة بيانات لعرض النتائج فعليًا
  }
}

function login() {
  const userInput = document.getElementById('loginInput').value.trim();
  if (userInput === "") {
    alert("يرجى إدخال البريد الإلكتروني أو رقم الهاتف.");
  } else {
    alert("✅ تم تسجيل الدخول كـ: " + userInput);
    // لاحقًا يمكن ربطه بـ Firebase للتسجيل الفعلي
  }
}
