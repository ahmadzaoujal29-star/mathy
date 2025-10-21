# -*- coding: utf-8 -*-
# مساعد الرياضيات بالذكاء الاصطناعي (نظام تعليمي مغربي)

import streamlit as st
import requests
import json
import os
import time
import base64
import bcrypt # ✨ التحديث الرئيسي: مكتبة التشفير الآمنة
from PIL import Image
from io import BytesIO
from datetime import date, timedelta

# *** المكتبات الضرورية ***
from supabase import create_client, Client
from streamlit_cookies_manager import EncryptedCookieManager

# --- Configuration et Paramètres de l'Application ---

st.set_page_config(
    page_title="Assistant IA Mathématiques (نظام المغربي)",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 1. تهيئة ملفات تعريف الارتباط (Cookies Initialization) ---
cookies = EncryptedCookieManager(
    prefix="gemini_math_app/",
    password=st.secrets.get("COOKIE_PASSWORD", "super_secret_default_key"),
)
if not cookies.ready():
    # يجب التوقف هنا لتجنب أي مشاكل إذا لم تكن الكوكيز جاهزة
    st.stop()
# -----------------------------------------------------------------

# Constantes et Secrets
MAX_REQUESTS = 5
ADMIN_EMAIL = st.secrets.get("ADMIN_EMAIL", "admin@example.com")
max_retries = 3
COOKIE_KEY_EMAIL = "user_auth_email"
SUPABASE_TABLE_NAME = "users" # اسم جدول المستخدمين

# Configuration de la clé API
API_KEY = st.secrets.get("GEMINI_API_KEY", "PLACEHOLDER_FOR_API_KEY")
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent"


# --- 2. تهيئة اتصال Supabase (Supabase Client Initialization) ---
try:
    supabase_url: str = st.secrets["SUPABASE_URL"]
    supabase_key: str = st.secrets["SUPABASE_KEY"]
    
    # إنشاء اتصال Supabase
    supabase: Client = create_client(supabase_url, supabase_key)
    users_table = supabase.table(SUPABASE_TABLE_NAME) # ✨ استخدام .table لتبسيط الكود
except KeyError:
    st.error("خطأ في المفاتيح السرية: يرجى التأكد من إضافة مفاتيح Supabase.")
    st.stop()
except Exception as e:
    st.error(f"خطأ في تهيئة اتصال Supabase: {e}")
    st.stop()
    
# --- تهيئة حالة الجلسة الافتراضية (Session State) ---
if 'auth_status' not in st.session_state: st.session_state.auth_status = 'logged_out'
if 'user_email' not in st.session_state: st.session_state.user_email = None
if 'user_data' not in st.session_state: st.session_state.user_data = None
if 'user_lang' not in st.session_state: st.session_state.user_lang = 'fr'
if 'response_type' not in st.session_state: st.session_state.response_type = 'steps'
if 'school_level' not in st.session_state: st.session_state.school_level = 'Tronc Commun'
if 'requests_today' not in st.session_state: st.session_state.requests_today = 0
if 'is_unlimited' not in st.session_state: st.session_state.is_unlimited = False


# --- دوال Supabase الفعلية (Database Functions) ---

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


def get_user_by_email(email: str):
    """استرجاع بيانات المستخدم من Supabase."""
    try:
        # استخدام .table(اسم الجدول).select
        response = users_table.select("*").eq("email", email).limit(1).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        st.error(f"خطأ في استرجاع بيانات المستخدم: {e}. (تحقق من اتصالك وشروط RLS).")
        return None

# ✨ التحديث 3: دالة تحديث بيانات المستخدم (محسّنة)
def update_user_data(email, data: dict, use_service_key=False):
    """تحديث بيانات المستخدم في Supabase."""
    client_to_use = supabase
    try:
        if use_service_key:
            # يجب أن يكون مفتاح الخدمة متاحاً في ملف secrets.toml
            service_key = st.secrets["SUPABASE_SERVICE_KEY"]
            client_to_use = create_client(supabase_url, service_key)
            
        response = client_to_use.table(SUPABASE_TABLE_NAME).update(data).eq("email", email).execute()
        
        if response.data:
            # تحديث حالة الجلسة ببيانات المستخدم الجديدة بعد التحديث
            if st.session_state.user_data:
                st.session_state.user_data.update(response.data[0])
            return True
        return False
    except KeyError:
        st.error("خطأ: مفتاح SUPABASE_SERVICE_KEY غير موجود في secrets.toml.")
        return False
    except Exception as e:
        st.error(f"خطأ في تحديث بيانات المستخدم في Supabase: {e}")
        return False

# --- وظائف المساعدين (Helper Functions) ---

def get_image_part(uploaded_file):
    # (لم يتغير: تم إبقاؤه كما هو)
    if uploaded_file is not None:
        bytes_data = uploaded_file.getvalue()
        mime_type = uploaded_file.type
        base64_encoded_data = base64.b64encode(bytes_data).decode('utf-8')
        
        return {
            "inlineData": {
                "data": base64_encoded_data,
                "mimeType": mime_type
            }
        }
    return None

def stream_text_simulation(text):
    # (لم يتغير: تم إبقاؤه كما هو)
    for chunk in text.split():
        yield chunk + " "
        time.sleep(0.02)

# --- الوظيفة الرئيسية: استدعاء API (API Call Function) ---

def call_gemini_api(prompt, image_part=None):
    
    if API_KEY == "PLACEHOLDER_FOR_API_KEY" or not API_KEY:
        st.error("Erreur de configuration : Veuillez ajouter la clé GEMINI_API_KEY.")
        return "Veuillez fournir une clé API valide.", []

    email = st.session_state.user_email
    user_data = st.session_state.user_data
    current_date_str = str(date.today())
    
    # 1. تطبيق حد الطلبات (Rate Limiting)
    if not user_data.get('is_unlimited', False):
        
        # ✨ التحديث 4: تحديث حالة الجلسة بناءً على آخر تاريخ طلب من Supabase
        if user_data.get('last_request_date') != current_date_str:
            # إعادة تعيين العداد لليوم الجديد
            st.session_state.requests_today = 0
            user_data['requests_today'] = 0
            user_data['last_request_date'] = current_date_str
            # تحديث قاعدة البيانات عند إعادة تعيين العداد
            update_user_data(email, {'requests_today': 0, 'last_request_date': current_date_str})

        current_count = st.session_state.requests_today

        if current_count >= MAX_REQUESTS:
            st.error(f"Limite atteinte : لقد وصلت إلى الحد الأقصى ({MAX_REQUESTS}) من الطلبات لهذا اليوم. يرجى العودة غداً.")
            return "Limite de requêtes atteinte.", []
            
        # نزيد العداد في حالة الجلسة مؤقتاً قبل استدعاء API
        st.session_state.requests_today = current_count + 1
        # تحديث عداد الجلسة

    # بناء التعليمات الأساسية (System Prompt)
    lang = user_data.get('lang', 'fr')
    response_type = user_data.get('response_type', 'steps')
    school_level = user_data.get('school_level', 'Tronc Commun')
    
    # (بقية بناء الـ system_prompt لم يتغير)
    system_prompt_base = f"Tu es un tuteur spécialisé en mathématiques, expert du système éducatif marocain (y compris le niveau '{school_level}'). Ta mission est de fournir une assistance précise et didactique. Si une image est fournie, tu dois l'analyser et résoudre le problème."

    if response_type == 'answer':
        style_instruction = "Fournis **uniquement la réponse النهائية** et concise du problème، sans aucune explication détaillée ni étapes intermédiaires."
    elif response_type == 'steps':
        style_instruction = "Fournis **les étapes détaillées de résolution** de manière structurée et méthodique pour aider l'étudiant à suivre le raisonnement."
    else:
        style_instruction = "Fournis **une explication conceptuelle approfondie** du problème ou du sujet المطلوب، و concentre-toi على النظريات والمفاهيم المتضمنة."
        
    if lang == 'fr':
        lang_instruction = "Tu dois répondre exclusivement en français."
    else:
        lang_instruction = "Tu dois répondre حصريًا باللغة العربية مع الحفاظ على المصطلحات الرياضية الأساسية بالفرنسية أو إدراج مقابلها العربي."

    final_system_prompt = f"{system_prompt_base} {lang_instruction} {style_instruction} Utilise le format Markdown pour organiser ta réponse, et assure-toi أن الصيغ الرياضية منسقة بـ LaTeX."


    contents_parts = []
    if image_part: contents_parts.append(image_part)
    if prompt: contents_parts.append({"text": prompt})
        
    if not contents_parts:
        return "Veuillez fournir une question أو صورة ليتمكن المدرس من مساعدتك.", []

    payload = {
        "contents": [{"parts": contents_parts}],
        # ✨ التحديث 5: إضافة Tool Calling للـ Google Search
        "tools": [{"google_search": {} }],
        "systemInstruction": final_system_prompt, # ✨ التحديث 6: استخدام نظام System Instruction الصحيح
    }

    headers = { 'Content-Type': 'application/json' }

    # آلية إعادة المحاولة
    for attempt in range(max_retries):
        try:
            full_url = f"{API_URL}?key={API_KEY}"
            
            response = requests.post(full_url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()
            
            result = response.json()
            
            # 2. تحديث العداد في قاعدة البيانات (فقط إذا لم يكن غير محدود)
            if not user_data.get('is_unlimited', False):
                # نحدث العداد وتاريخ آخر طلب
                update_user_data(email, {'requests_today': st.session_state.requests_today, 'last_request_date': current_date_str})
                
            candidate = result.get('candidates', [None])[0]
            
            if candidate and candidate.get('content') and candidate['content'].get('parts'):
                generated_text = candidate['content']['parts'][0].get('text', "Aucun texte trouvé.")
                
                # استخراج المصادر (Sources)
                sources = []
                grounding_metadata = candidate.get('groundingMetadata')
                if grounding_metadata and grounding_metadata.get('groundingAttributions'):
                    sources = [
                        { 'uri': attr.get('web', {}).get('uri'), 'title': attr.get('web', {}).get('title'),}
                        for attr in grounding_metadata['groundingAttributions']
                        if attr.get('web', {}).get('title')
                    ]
                
                return generated_text, sources
            else:
                return "Désolé، le modèle n'a pas pu توفير رد. Veuillez essayer مع طلب آخر.", []

        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            return f"فشل في الاتصال بعد {max_retries} محاولات: {e}", []
        except Exception as e:
            return f"خطأ غير متوقع: {e}", []
    
    return "فشلت عملية إنشاء الإجابة.", []

# --- دوال المصادقة (Authentication Functions) ---

def load_user_session(email, save_cookie=False):
    # (وظيفة جيدة، تم إبقاؤها مع بعض التعديلات البسيطة لـ RLS)
    user_data = get_user_by_email(email)
    
    if user_data:
        if save_cookie:
            cookies[COOKIE_KEY_EMAIL] = email
            cookies.save()
            st.toast("تم حفظ معلومات الدخول.")
            
        st.session_state.user_email = email
        st.session_state.user_data = user_data
        st.session_state.user_lang = user_data.get('lang', 'fr')
        st.session_state.response_type = user_data.get('response_type', 'steps')
        st.session_state.school_level = user_data.get('school_level', 'Tronc Commun')
        st.session_state.is_unlimited = user_data.get('is_unlimited', False)
        
        current_date_str = str(date.today())
        
        # تحديث حالة الجلسة بالعداد الصحيح
        if user_data.get('last_request_date') != current_date_str:
            st.session_state.requests_today = 0
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
    password = st.session_state.login_password
    
    user_data = get_user_by_email(email)
    
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
    password = st.session_state.reg_password
    confirm_password = st.session_state.reg_password_confirm
    
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
        'password_hash': hash_password(password), # استخدام bcrypt
        'lang': st.session_state.reg_lang,
        'response_type': st.session_state.reg_response_type,
        'school_level': st.session_state.reg_school_level,
        'is_unlimited': False,
        'requests_today': 0,
        'last_request_date': str(date.today()),
    }
    
    try:
        # استخدام users_table
        users_table.insert([new_user_data]).execute()
        st.success("تم التسجيل والدخول بنجاح! 🥳")
        load_user_session(email, save_cookie=True)
        st.experimental_rerun()
    except Exception as e:
        st.error(f"فشل في التسجيل: {e}. (تأكد من إعداد RLS لعملية INSERT).")


def handle_logout():
    # (لم يتغير: تم إبقاؤه كما هو)
    cookies[COOKIE_KEY_EMAIL] = ''
    cookies.save()
    st.session_state.auth_status = 'logged_out'
    st.session_state.user_email = None
    st.session_state.user_data = None
    st.session_state.requests_today = 0
    st.success("Déconnexion réussie.")
    st.experimental_rerun()

def handle_save_settings():
    # (تم إبقاؤها كما هي - تستخدم update_user_data المحسّنة)
    email = st.session_state.user_email

    new_data = {
        'lang': st.session_state.settings_lang,
        'response_type': st.session_state.settings_response_type,
        'school_level': st.session_state.settings_school_level,
    }
    
    if update_user_data(email, new_data):
        st.session_state.user_lang = st.session_state.settings_lang
        st.session_state.response_type = st.session_state.settings_response_type
        st.session_state.school_level = st.session_state.settings_school_level
        st.success("Préférences sauvegardées بنجاح!")
        st.experimental_rerun()
    else:
        st.error("خطأ: لم يتم حفظ التفضيلات.")

# ✨ التحديث 9: استخدام hash_password الآمن في تغيير كلمة المرور
def handle_change_password():
    email = st.session_state.user_email
    new_password = st.session_state.new_password
    confirm_new_password = st.session_state.confirm_new_password

    if not new_password or new_password != confirm_new_password:
        st.error("كلمات المرور الجديدة غير متطابقة.")
        return
    
    if len(new_password) < 6:
        st.error("يجب أن تتكون كلمة المرور من 6 أحرف على الأقل.")
        return

    # تحديث كلمة المرور في Supabase (نستخدم الدالة العامة للتحديث)
    if update_user_data(email, {'password_hash': hash_password(new_password)}):
        st.success("تم تغيير كلمة المرور بنجاح! 🔑")
        # مسح حقول الإدخال بعد النجاح
        st.session_state.new_password = ''
        st.session_state.confirm_new_password = ''
    else:
        st.error("خطأ في تحديث كلمة المرور.")


def toggle_unlimited_use(target_email, current_status):
    # (تم إبقاؤها كما هي - تستخدم update_user_data المحسّنة)
    new_status = not current_status
    if update_user_data(target_email, {'is_unlimited': new_status}, use_service_key=True):
        st.success(f"تم تحديث المستخدم **{target_email}**: الاستخدام غير المحدود الآن: {new_status}")
    else:
        st.error(f"فشل تحديث المستخدم {target_email}")


# --- واجهات المستخدم (UI Components) ---

def auth_ui():
    # (لم تتغير)
    st.header("Connexion / التسجيل")
    st.markdown("---")

    col1, col2 = st.columns(2)
    
    with col1:
        with st.form("login_form"):
            st.subheader("Se Connecter")
            st.text_input("Email", key="login_email")
            st.text_input("Mot de passe", type="password", key="login_password")
            st.form_submit_button("Connexion", on_click=handle_login)

    with col2:
        with st.form("register_form"):
            st.subheader("S'inscrire")
            st.text_input("Email", key="reg_email")
            st.text_input("Mot de passe", type="password", key="reg_password")
            st.text_input("Confirmer le mot de passe", type="password", key="reg_password_confirm")
            
            st.subheader("Vos Préférences (Éducation Maroc)")
            
            school_levels = ['Tronc Commun', '1ère Année Bac (Sciences)', '2ème Année Bac (Sciences Maths A)', '2ème Année Bac (Sciences Maths B)', '2ème Année Bac (Sciences Expérimentales)', 'Écoles Supérieures/Classes Préparatoires']
            st.selectbox("Niveau Scolaire", options=school_levels, key="reg_school_level")
            
            st.radio("Langue Préférée", options=['fr', 'ar'], format_func=lambda x: 'Français' if x == 'fr' else 'العربية', key="reg_lang")
            
            response_options = {'answer': 'Réponse Finale Seulement', 'steps': 'Étapes Détaillées', 'explanation': 'Explication Conceptuelle'}
            st.selectbox("Genre de Réponse", options=list(response_options.keys()), format_func=lambda x: response_options[x], key="reg_response_type")

            st.form_submit_button("S'inscrire", on_click=handle_register)


def admin_dashboard_ui():
    # (تم تحسينه للتعامل مع المفتاح لضمان الوصول لجميع المستخدمين)
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("👑 لوحة تحكم المشرف")
    
    try:
        # نستخدم مفتاح الخدمة للحصول على قائمة جميع المستخدمين
        service_key = st.secrets["SUPABASE_SERVICE_KEY"]
        admin_client = create_client(supabase_url, service_key)
        
        # جلب جميع المستخدمين باستثناء المشرف نفسه
        response = admin_client.table(SUPABASE_TABLE_NAME).select("*").neq("email", ADMIN_EMAIL).execute()
        all_users = response.data
    except KeyError:
        st.sidebar.error("فشل: مفتاح SUPABASE_SERVICE_KEY غير موجود.")
        return
    except Exception as e:
        st.sidebar.error(f"فشل جلب قائمة المستخدمين: {e}")
        return

    if not all_users:
        st.sidebar.write("لا يوجد مستخدمون مسجلون غير المشرف.")
        return

    st.sidebar.markdown("**قائمة






