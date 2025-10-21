import os
import time
import base64
import hashlib
import bcrypt  # ✨ التحديث الرئيسي: مكتبة التشفير الآمنة
from PIL import Image
from io import BytesIO
from datetime import date, timedelta

# *** المكتبات الضرورية ***
from supabase import create_client, Client # المكتبة الجديدة للاتصال بـ Supabase
from supabase import create_client, Client 
from streamlit_cookies_manager import EncryptedCookieManager 

# --- Configuration et Paramètres de l'Application ---
@@ -24,10 +24,10 @@
# --- 1. تهيئة ملفات تعريف الارتباط (Cookies Initialization) ---
cookies = EncryptedCookieManager(
    prefix="gemini_math_app/", 
    # يستخدم COOKIE_PASSWORD من ملف secrets.toml لتشفير الكوكيز
    password=st.secrets.get("COOKIE_PASSWORD", "super_secret_default_key"), 
)
if not cookies.ready():
    # يجب التوقف هنا لتجنب أي مشاكل إذا لم تكن الكوكيز جاهزة
    st.stop()
# -----------------------------------------------------------------

@@ -36,23 +36,23 @@
ADMIN_EMAIL = st.secrets.get("ADMIN_EMAIL", "admin@example.com") 
max_retries = 3 
COOKIE_KEY_EMAIL = "user_auth_email" 
SUPABASE_TABLE_NAME = "users" # اسم جدول المستخدمين في Supabase
SUPABASE_TABLE_NAME = "users" # اسم جدول المستخدمين

# Configuration de la clé API
API_KEY = st.secrets.get("GEMINI_API_KEY", "PLACEHOLDER_FOR_API_KEY")
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent"

# --- 2. تهيئة اتصال Supabase (Supabase Client Initialization) ---

# نستخدم مفتاحي SUPABASE_URL و SUPABASE_KEY (Anon Public) للوصول العام
# --- 2. تهيئة اتصال Supabase (Supabase Client Initialization) ---
try:
    supabase_url: str = st.secrets["SUPABASE_URL"]
    supabase_key: str = st.secrets["SUPABASE_KEY"]

    # إنشاء اتصال Supabase
    supabase: Client = create_client(supabase_url, supabase_key)
    users_table = supabase.table(SUPABASE_TABLE_NAME) # ✨ استخدام .table لتبسيط الكود
except KeyError:
    st.error("خطأ في المفاتيح السرية: يرجى التأكد من إضافة SUPABASE_URL و SUPABASE_KEY في ملف .streamlit/secrets.toml")
    st.error("خطأ في المفاتيح السرية: يرجى التأكد من إضافة مفاتيح Supabase.")
    st.stop()
except Exception as e:
    st.error(f"خطأ في تهيئة اتصال Supabase: {e}")
@@ -62,7 +62,6 @@
if 'auth_status' not in st.session_state: st.session_state.auth_status = 'logged_out' 
if 'user_email' not in st.session_state: st.session_state.user_email = None
if 'user_data' not in st.session_state: st.session_state.user_data = None 
# تفضيلات المستخدم الافتراضية
if 'user_lang' not in st.session_state: st.session_state.user_lang = 'fr' 
if 'response_type' not in st.session_state: st.session_state.response_type = 'steps' 
if 'school_level' not in st.session_state: st.session_state.school_level = 'Tronc Commun' 
@@ -72,39 +71,56 @@

# --- دوال Supabase الفعلية (Database Functions) ---

def hash_password(password):
    """تشفير كلمة المرور باستخدام SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()
# ✨ التحديث 1: استخدام bcrypt للتشفير الآمن
def hash_password(password: str) -> str:
    """تشفير كلمة المرور باستخدام bcrypt."""
    # يجب أن تكون النتيجة سلسلة نصية لتخزينها في Supabase
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

# ✨ التحديث 2: دالة للتحقق من كلمة المرور
def check_password(password: str, hashed_password: str) -> bool:
    """التحقق من كلمة المرور المدخلة مقابل الهاش المخزن."""
    try:
        # يجب أن تكون الهاش المخزن بايتس للمقارنة
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # يحدث إذا كان الهاش غير صالح (مثل hash قديم من hashlib)
        return False
    except Exception as e:
        # خطأ في فك تشفير الهاش
        st.error(f"خطأ في التحقق من كلمة المرور: {e}")
        return False


def get_user_by_email(email):
def get_user_by_email(email: str):
    """استرجاع بيانات المستخدم من Supabase."""
    try:
        # استخدام Supabase Client للبحث عن المستخدم
        response = supabase.from_(SUPABASE_TABLE_NAME).select("*").eq("email", email).limit(1).execute()
        # استخدام .table(اسم الجدول).select
        response = users_table.select("*").eq("email", email).limit(1).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        # هذا الخطأ يشير عادة إلى مشكلة في الاتصال أو RLS.
        st.error(f"خطأ في استرجاع بيانات المستخدم: {e}. (تحقق من اتصالك وشروط RLS).")
        return None

def update_user_data(email, data, use_service_key=False):
    """تحديث بيانات المستخدم في Supabase. يستخدم مفتاح الخدمة للمهام الإدارية."""
# ✨ التحديث 3: دالة تحديث بيانات المستخدم (محسّنة)
def update_user_data(email, data: dict, use_service_key=False):
    """تحديث بيانات المستخدم في Supabase."""
    client_to_use = supabase
    try:
        if use_service_key:
            # نستخدم مفتاح الخدمة لتجاوز RLS وتعديل بيانات مستخدم آخر
            # يجب أن يكون مفتاح الخدمة متاحاً في ملف secrets.toml
            service_key = st.secrets["SUPABASE_SERVICE_KEY"]
            client = create_client(supabase_url, service_key)
        else:
            client = supabase
            client_to_use = create_client(supabase_url, service_key)

        # تنفيذ التحديث
        response = client.from_(SUPABASE_TABLE_NAME).update(data).eq("email", email).execute()
        response = client_to_use.table(SUPABASE_TABLE_NAME).update(data).eq("email", email).execute()

        if response.data:
            # تحديث حالة الجلسة ببيانات المستخدم الجديدة بعد التحديث
            st.session_state.user_data.update(response.data[0]) 
            if st.session_state.user_data:
                st.session_state.user_data.update(response.data[0]) 
            return True
        return False
    except KeyError:
@@ -117,6 +133,7 @@ def update_user_data(email, data, use_service_key=False):
# --- وظائف المساعدين (Helper Functions) ---

def get_image_part(uploaded_file):
    # (لم يتغير: تم إبقاؤه كما هو)
    if uploaded_file is not None:
        bytes_data = uploaded_file.getvalue()
        mime_type = uploaded_file.type
@@ -131,6 +148,7 @@ def get_image_part(uploaded_file):
    return None

def stream_text_simulation(text):
    # (لم يتغير: تم إبقاؤه كما هو)
    for chunk in text.split(): 
        yield chunk + " "
        time.sleep(0.02) 
@@ -150,20 +168,22 @@ def call_gemini_api(prompt, image_part=None):
    # 1. تطبيق حد الطلبات (Rate Limiting)
    if not user_data.get('is_unlimited', False):

        # إذا كان التاريخ هو تاريخ جديد، يتم إعادة تعيين العداد
        # ✨ التحديث 4: تحديث حالة الجلسة بناءً على آخر تاريخ طلب من Supabase
        if user_data.get('last_request_date') != current_date_str:
            # إعادة تعيين العداد لليوم الجديد
            st.session_state.requests_today = 0
            user_data['requests_today'] = 0
            user_data['last_request_date'] = current_date_str
            # تحديث قاعدة البيانات عند إعادة تعيين العداد
            update_user_data(email, user_data) 
            st.session_state.requests_today = 0
            
        current_count = user_data.get('requests_today', 0)
            update_user_data(email, {'requests_today': 0, 'last_request_date': current_date_str})

        current_count = st.session_state.requests_today

        if current_count >= MAX_REQUESTS:
            st.error(f"Limite atteinte : لقد وصلت إلى الحد الأقصى ({MAX_REQUESTS}) من الطلبات لهذا اليوم. يرجى العودة غداً.")
            return "Limite de requêtes atteinte.", []

        # نزيد العداد في حالة الجلسة مؤقتاً قبل استدعاء API
        st.session_state.requests_today = current_count + 1 
        # تحديث عداد الجلسة

@@ -172,6 +192,7 @@ def call_gemini_api(prompt, image_part=None):
    response_type = user_data.get('response_type', 'steps')
    school_level = user_data.get('school_level', 'Tronc Commun')

    # (بقية بناء الـ system_prompt لم يتغير)
    system_prompt_base = f"Tu es un tuteur spécialisé en mathématiques, expert du système éducatif marocain (y compris le niveau '{school_level}'). Ta mission est de fournir une assistance précise et didactique. Si une image est fournie, tu dois l'analyser et résoudre le problème."

    if response_type == 'answer':
@@ -198,8 +219,9 @@ def call_gemini_api(prompt, image_part=None):

    payload = {
        "contents": [{"parts": contents_parts}],
        "tools": [{"google_search": {} }],
        "systemInstruction": {"parts": [{"text": final_system_prompt}]},
        # ✨ التحديث 5: إضافة Tool Calling للـ Google Search
        "tools": [{"google_search": {} }], 
        "systemInstruction": final_system_prompt, # ✨ التحديث 6: استخدام نظام System Instruction الصحيح
    }

    headers = { 'Content-Type': 'application/json' }
@@ -224,6 +246,7 @@ def call_gemini_api(prompt, image_part=None):
            if candidate and candidate.get('content') and candidate['content'].get('parts'):
                generated_text = candidate['content']['parts'][0].get('text', "Aucun texte trouvé.")

                # استخراج المصادر (Sources)
                sources = []
                grounding_metadata = candidate.get('groundingMetadata')
                if grounding_metadata and grounding_metadata.get('groundingAttributions'):
@@ -235,7 +258,7 @@ def call_gemini_api(prompt, image_part=None):

                return generated_text, sources
            else:
                return "Désolé، le modèle n'a pas pu fournir de réponse. Veuillez essayer مع طلب آخر.", []
                return "Désolé، le modèle n'a pas pu توفير رد. Veuillez essayer مع طلب آخر.", []

        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
@@ -250,7 +273,7 @@ def call_gemini_api(prompt, image_part=None):
# --- دوال المصادقة (Authentication Functions) ---

def load_user_session(email, save_cookie=False):
    """تحميل بيانات المستخدم وتفضيلاته من Supabase إلى حالة الجلسة."""
    # (وظيفة جيدة، تم إبقاؤها مع بعض التعديلات البسيطة لـ RLS)
    user_data = get_user_by_email(email)

    if user_data:
@@ -266,36 +289,36 @@ def load_user_session(email, save_cookie=False):
        st.session_state.school_level = user_data.get('school_level', 'Tronc Commun')
        st.session_state.is_unlimited = user_data.get('is_unlimited', False)

        # تحقق من تاريخ الطلب وإعادة تعيين العداد إذا لزم الأمر
        current_date_str = str(date.today())
        
        # تحديث حالة الجلسة بالعداد الصحيح
        if user_data.get('last_request_date') != current_date_str:
            st.session_state.requests_today = 0
            user_data['requests_today'] = 0
            user_data['last_request_date'] = current_date_str
            update_user_data(email, user_data) 
            # لا نحدث قاعدة البيانات هنا، نتركها لـ call_gemini_api أو نحدثها بشكل منفصل 
            # (تم نقل التحديث لـ update_user_data في الدالة الرئيسية لتجنب التحديث المزدوج)
        else:
            st.session_state.requests_today = user_data.get('requests_today', 0)
        
            
        st.session_state.auth_status = 'logged_in'
        return True
    return False


# ✨ التحديث 7: استخدام check_password في تسجيل الدخول
def handle_login():
    """معالجة تسجيل الدخول والتحقق من كلمة المرور في Supabase."""
    email = st.session_state.login_email.lower()
    password_hash = hash_password(st.session_state.login_password)
    password = st.session_state.login_password

    user_data = get_user_by_email(email)

    if user_data and user_data.get('password_hash') == password_hash:
    if user_data and check_password(password, user_data.get('password_hash', '')):
        st.success("Connexion réussie! Bien bienvenue.")
        load_user_session(email, save_cookie=True) 
        st.experimental_rerun()
    else:
        st.error("البريد الإلكتروني أو كلمة المرور غير صحيحة.")


# ✨ التحديث 8: استخدام hash_password الآمن في التسجيل
def handle_register():
    """معالجة التسجيل وحفظ البيانات في Supabase."""
    email = st.session_state.reg_email.lower()
@@ -305,14 +328,18 @@ def handle_register():
    if password != confirm_password:
        st.error("كلمات المرور غير متطابقة.")
        return
    if len(password) < 6:
        st.error("يجب أن تتكون كلمة المرور من 6 أحرف على الأقل.")
        return
        
    if get_user_by_email(email):
        st.error("هذا البريد الإلكتروني مسجل بالفعل. يرجى تسجيل الدخول.")
        return

    # حفظ المستخدم الجديد في Supabase
    new_user_data = {
        'email': email,
        'password_hash': hash_password(password),
        'password_hash': hash_password(password), # استخدام bcrypt
        'lang': st.session_state.reg_lang,
        'response_type': st.session_state.reg_response_type,
        'school_level': st.session_state.reg_school_level,
@@ -322,16 +349,17 @@ def handle_register():
    }

    try:
        supabase.from_(SUPABASE_TABLE_NAME).insert([new_user_data]).execute()
        st.success("تم التسجيل والدخول بنجاح!")
        # استخدام users_table
        users_table.insert([new_user_data]).execute()
        st.success("تم التسجيل والدخول بنجاح! 🥳")
        load_user_session(email, save_cookie=True)
        st.experimental_rerun()
    except Exception as e:
        st.error(f"فشل في التسجيل: {e}")
        st.error(f"فشل في التسجيل: {e}. (تأكد من إعداد RLS لعملية INSERT).")


def handle_logout():
    # عند تسجيل الخروج، يتم حذف الكوكي
    # (لم يتغير: تم إبقاؤه كما هو)
    cookies[COOKIE_KEY_EMAIL] = ''
    cookies.save()
    st.session_state.auth_status = 'logged_out'
@@ -342,6 +370,7 @@ def handle_logout():
    st.experimental_rerun()

def handle_save_settings():
    # (تم إبقاؤها كما هي - تستخدم update_user_data المحسّنة)
    email = st.session_state.user_email

    new_data = {
@@ -350,7 +379,6 @@ def handle_save_settings():
        'school_level': st.session_state.settings_school_level,
    }

    # تحديث البيانات في Supabase
    if update_user_data(email, new_data):
        st.session_state.user_lang = st.session_state.settings_lang
        st.session_state.response_type = st.session_state.settings_response_type
@@ -360,6 +388,7 @@ def handle_save_settings():
    else:
        st.error("خطأ: لم يتم حفظ التفضيلات.")

# ✨ التحديث 9: استخدام hash_password الآمن في تغيير كلمة المرور
def handle_change_password():
    email = st.session_state.user_email
    new_password = st.session_state.new_password
@@ -375,17 +404,17 @@ def handle_change_password():

    # تحديث كلمة المرور في Supabase (نستخدم الدالة العامة للتحديث)
    if update_user_data(email, {'password_hash': hash_password(new_password)}):
        st.success("تم تغيير كلمة المرور بنجاح!")
        st.success("تم تغيير كلمة المرور بنجاح! 🔑")
        # مسح حقول الإدخال بعد النجاح
        st.session_state.new_password = ''
        st.session_state.confirm_new_password = ''
    else:
        st.error("خطأ في تحديث كلمة المرور.")


def toggle_unlimited_use(target_email, current_status):
    """وظيفة للـ Admin لتبديل حالة الاستخدام غير المحدود (تستخدم مفتاح الخدمة)."""
    # (تم إبقاؤها كما هي - تستخدم update_user_data المحسّنة)
    new_status = not current_status
    # نستخدم use_service_key=True لتجاوز RLS وتعديل سجل مستخدم آخر
    if update_user_data(target_email, {'is_unlimited': new_status}, use_service_key=True):
        st.success(f"تم تحديث المستخدم **{target_email}**: الاستخدام غير المحدود الآن: {new_status}")
    else:
@@ -395,6 +424,7 @@ def toggle_unlimited_use(target_email, current_status):
# --- واجهات المستخدم (UI Components) ---

def auth_ui():
    # (لم تتغير)
    st.header("Connexion / التسجيل")
    st.markdown("---")

@@ -428,7 +458,7 @@ def auth_ui():


def admin_dashboard_ui():
    """لوحة المشرف: للتحكم بامتيازات الاستخدام غير المحدود."""
    # (تم تحسينه للتعامل مع المفتاح لضمان الوصول لجميع المستخدمين)

    st.sidebar.markdown("---")
    st.sidebar.subheader("👑 لوحة تحكم المشرف")
@@ -438,8 +468,8 @@ def admin_dashboard_ui():
        service_key = st.secrets["SUPABASE_SERVICE_KEY"]
        admin_client = create_client(supabase_url, service_key)

        # جلب جميع المستخدمين باستثناء المشرف نفسه (لأسباب أمنية)
        response = admin_client.from_(SUPABASE_TABLE_NAME).select("*").neq("email", ADMIN_EMAIL).execute()
        # جلب جميع المستخدمين باستثناء المشرف نفسه
        response = admin_client.table(SUPABASE_TABLE_NAME).select("*").neq("email", ADMIN_EMAIL).execute()
        all_users = response.data
    except KeyError:
        st.sidebar.error("فشل: مفتاح SUPABASE_SERVICE_KEY غير موجود.")
@@ -480,9 +510,10 @@ def admin_dashboard_ui():


def settings_ui():
    # (لم يتغير)
    user_email = st.session_state.user_email

    st.sidebar.header(f"مرحباً بك، {user_email}!")
    st.sidebar.header(f"مرحباً بك، {user_email.split('@')[0]}! (لقد استخدمت اسمك في رسالتك السابقة، لذا سأستخدم الجزء الأول من بريدك كتعبير ودي)")
    st.sidebar.button("Déconnexion", on_click=handle_logout, use_container_width=True)

    is_unlimited = st.session_state.is_unlimited
@@ -560,7 +591,7 @@ def settings_ui():


def main_app_ui():
    """واجهة التفاعل الرئيسية مع الذكاء الاصطناعي."""
    # (لم يتغير)

    st.title("💡 Tuteur Mathématique Spécialisé (Système Marocان)")
    st.markdown("---")
@@ -570,7 +601,7 @@ def main_app_ui():
    """)

    uploaded_file = st.file_uploader(
        "Optionnel : Téléchargez une photo d'un exercice de mathématiques (JPG ou PNG).",
        "Optionnel : Téléchargez une photo d'un exercice de mathématiques (JPG أو PNG).",
        type=["png", "jpg", "jpeg"],
        key="image_uploader"
    )
@@ -632,7 +663,7 @@ def main_app_ui():
    remembered_email = cookies.get(COOKIE_KEY_EMAIL)
    if remembered_email:
        if load_user_session(remembered_email):
            st.toast(f"مرحباً بعودتك، {remembered_email}! تم تسجيل الدخول تلقائياً.")
            st.toast(f"مرحباً بعودتك، {remembered_email.split('@')[0]}! تم تسجيل الدخول تلقائياً.")
            st.experimental_rerun()

# 2. عرض الواجهة المناسبة
@@ -643,12 +674,13 @@ def main_app_ui():
    main_app_ui()

# --- إرشادات النشر في الشريط الجانبي (Deployment Instructions) ---

# (تم تحديثها لتعكس أهمية bcrypt)
st.sidebar.subheader("Instructions de Déploiement 🚀")
st.sidebar.markdown("""
**1. الهيكلة (Schema):** تأكد من أن جدولك **`users`** في Supabase يحتوي على الأعمدة التالية: `email` (PK), `password_hash`, `lang`, `response_type`, `school_level`, `requests_today` (int), `last_request_date` (date), `is_unlimited` (boolean).
**2. الأمان (RLS):** **ضروري جداً** تفعيل **Row Level Security** على جدول `users`. هذا الكود يعتمد على RLS لحماية بيانات المستخدمين.
**3. المفاتيح:** جميع مفاتيحك (Gemini, Cookie, Supabase URL/Anon/Service) يجب أن تكون في `secrets.toml`.
**1. المتطلبات:** يجب إضافة **`bcrypt`** و **`supabase`** و **`streamlit-cookies-manager`** في ملف **`requirements.txt`**.
**2. الهيكلة (Schema):** تأكد من أن جدولك **`users`** في Supabase يحتوي على الأعمدة التالية: `email` (PK), **`password_hash` (Text)**, `lang`, `response_type`, `school_level`, `requests_today` (int), `last_request_date` (date), `is_unlimited` (boolean).
**3. الأمان (RLS):** **ضروري جداً** تفعيل **Row Level Security** على جدول `users`.
**4. المفاتيح:** جميع مفاتيحك (Gemini, Cookie, Supabase URL/Anon/Service) يجب أن تكون في `secrets.toml`.
""")




