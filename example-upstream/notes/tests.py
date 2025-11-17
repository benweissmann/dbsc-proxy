from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from .models import Note


class UserRegistrationTests(TestCase):
    """Test user registration functionality"""

    def setUp(self):
        self.client = Client()
        self.register_url = reverse("register")

    def test_register_page_loads(self):
        """Test that the registration page loads successfully"""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "form")

    def test_successful_registration(self):
        """Test successful user registration with valid data"""
        response = self.client.post(
            self.register_url,
            {
                "username": "testuser",
                "password1": "testpass123!@#",
                "password2": "testpass123!@#",
            },
        )
        # Should redirect to dashboard after successful registration
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("dashboard"))

        # Verify user was created
        self.assertTrue(User.objects.filter(username="testuser").exists())

        # Verify user is logged in
        user = User.objects.get(username="testuser")
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.pk)

    def test_registration_with_mismatched_passwords(self):
        """Test registration fails when passwords don't match"""
        response = self.client.post(
            self.register_url,
            {
                "username": "testuser",
                "password1": "testpass123!@#",
                "password2": "differentpass456!@#",
            },
        )
        # Should stay on registration page
        self.assertEqual(response.status_code, 200)
        # User should not be created
        self.assertFalse(User.objects.filter(username="testuser").exists())

    def test_registration_with_existing_username(self):
        """Test registration fails when username already exists"""
        # Create existing user
        User.objects.create_user(username="testuser", password="oldpass123!@#")

        response = self.client.post(
            self.register_url,
            {
                "username": "testuser",
                "password1": "testpass123!@#",
                "password2": "testpass123!@#",
            },
        )
        # Should stay on registration page with error
        self.assertEqual(response.status_code, 200)
        # Should only have one user with this username
        self.assertEqual(User.objects.filter(username="testuser").count(), 1)


class UserLoginLogoutTests(TestCase):
    """Test user login and logout functionality"""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse("login")
        self.logout_url = reverse("logout")
        self.dashboard_url = reverse("dashboard")

        # Create a test user
        self.username = "testuser"
        self.password = "testpass123!@#"
        self.user = User.objects.create_user(
            username=self.username, password=self.password
        )

    def test_login_page_loads(self):
        """Test that the login page loads successfully"""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "form")

    def test_successful_login(self):
        """Test successful login with valid credentials"""
        response = self.client.post(
            self.login_url,
            {
                "username": self.username,
                "password": self.password,
            },
        )
        # Should redirect after successful login
        self.assertEqual(response.status_code, 302)

        # Verify user is logged in
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)

    def test_login_with_invalid_credentials(self):
        """Test login fails with invalid credentials"""
        response = self.client.post(
            self.login_url,
            {
                "username": self.username,
                "password": "wrongpassword",
            },
        )
        # Should stay on login page
        self.assertEqual(response.status_code, 200)
        # User should not be logged in
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_logout(self):
        """Test user logout functionality"""
        # First login
        self.client.login(username=self.username, password=self.password)
        self.assertIn("_auth_user_id", self.client.session)

        # Then logout
        response = self.client.post(self.logout_url)
        # Should redirect after logout
        self.assertEqual(response.status_code, 302)

        # Verify user is logged out
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_dashboard_requires_login(self):
        """Test that dashboard requires authentication"""
        response = self.client.get(self.dashboard_url)
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith("/accounts/login/"))  # type: ignore


class NoteCreationTests(TestCase):
    """Test note creation functionality"""

    def setUp(self):
        self.client = Client()
        self.dashboard_url = reverse("dashboard")

        # Create and login a test user
        self.username = "testuser"
        self.password = "testpass123!@#"
        self.user = User.objects.create_user(
            username=self.username, password=self.password
        )
        self.client.login(username=self.username, password=self.password)

    def test_note_created_on_first_dashboard_visit(self):
        """
        Test that a note is automatically created when user first visits
        dashboard
        """
        # Verify no note exists initially
        self.assertFalse(Note.objects.filter(user=self.user).exists())

        # Visit dashboard
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)

        # Verify note was created
        self.assertTrue(Note.objects.filter(user=self.user).exists())
        note = Note.objects.get(user=self.user)
        self.assertEqual(note.note_text, "")

    def test_create_note_with_text(self):
        """Test creating a note with initial text"""
        note_text = "This is my first note!"

        response = self.client.post(self.dashboard_url, {"note_text": note_text})

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.dashboard_url)

        # Verify note was created with correct text
        self.assertTrue(Note.objects.filter(user=self.user).exists())
        note = Note.objects.get(user=self.user)
        self.assertEqual(note.note_text, note_text)

    def test_only_one_note_per_user(self):
        """Test that each user can only have one note"""
        # Create first note
        self.client.post(self.dashboard_url, {"note_text": "First note"})
        self.assertEqual(Note.objects.filter(user=self.user).count(), 1)

        # Try to create another note (should update existing)
        self.client.post(self.dashboard_url, {"note_text": "Second note"})
        self.assertEqual(Note.objects.filter(user=self.user).count(), 1)

        # Verify text was updated
        note = Note.objects.get(user=self.user)
        self.assertEqual(note.note_text, "Second note")


class NoteUpdateTests(TestCase):
    """Test note update functionality"""

    def setUp(self):
        self.client = Client()
        self.dashboard_url = reverse("dashboard")

        # Create and login a test user
        self.username = "testuser"
        self.password = "testpass123!@#"
        self.user = User.objects.create_user(
            username=self.username, password=self.password
        )
        self.client.login(username=self.username, password=self.password)

        # Create an initial note
        self.note = Note.objects.create(user=self.user, note_text="Initial note text")

    def test_update_note_text(self):
        """Test updating existing note text"""
        new_text = "Updated note text"
        response = self.client.post(self.dashboard_url, {"note_text": new_text})

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.dashboard_url)

        # Verify note was updated
        self.note.refresh_from_db()
        self.assertEqual(self.note.note_text, new_text)

    def test_update_note_to_empty(self):
        """Test updating note to empty text"""
        response = self.client.post(self.dashboard_url, {"note_text": ""})

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)

        # Verify note was updated to empty
        self.note.refresh_from_db()
        self.assertEqual(self.note.note_text, "")

    def test_update_note_multiple_times(self):
        """Test updating note multiple times"""
        updates = [
            "First update",
            "Second update",
            "Third update",
        ]

        for update_text in updates:
            response = self.client.post(self.dashboard_url, {"note_text": update_text})
            self.assertEqual(response.status_code, 302)
            self.note.refresh_from_db()
            self.assertEqual(self.note.note_text, update_text)

        # Verify still only one note exists
        self.assertEqual(Note.objects.filter(user=self.user).count(), 1)

    def test_note_timestamps_update(self):
        """Test that updated_at timestamp changes on update"""
        original_updated_at = self.note.updated_at

        # Wait a tiny bit to ensure timestamp difference
        import time

        time.sleep(0.01)

        # Update note
        self.client.post(self.dashboard_url, {"note_text": "New text"})
        self.note.refresh_from_db()

        # Verify updated_at changed
        self.assertGreater(self.note.updated_at, original_updated_at)
        # Verify created_at stayed the same
        self.assertEqual(self.note.created_at, self.note.created_at)


class IndexViewTests(TestCase):
    """Test index page functionality"""

    def setUp(self):
        self.client = Client()
        self.index_url = reverse("index")
        self.dashboard_url = reverse("dashboard")

    def test_index_page_loads_for_anonymous_user(self):
        """Test that index page loads for non-authenticated users"""
        response = self.client.get(self.index_url)
        self.assertEqual(response.status_code, 200)

    def test_authenticated_user_redirected_to_dashboard(self):
        """
        Test that authenticated users are redirected to dashboard from
        index
        """
        # Create and login user
        User.objects.create_user(username="testuser", password="testpass123!@#")
        self.client.login(username="testuser", password="testpass123!@#")

        # Try to access index
        response = self.client.get(self.index_url)

        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.dashboard_url)
