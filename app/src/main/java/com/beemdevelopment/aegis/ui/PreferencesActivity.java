package com.beemdevelopment.aegis.ui;

import android.net.Uri;
import android.os.Bundle;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;

import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.ui.fragments.preferences.AppearancePreferencesFragment;
import com.beemdevelopment.aegis.ui.fragments.preferences.MainPreferencesFragment;
import com.beemdevelopment.aegis.ui.fragments.preferences.PreferencesFragment;
import com.beemdevelopment.aegis.helpers.ViewHelper;

public class PreferencesActivity extends AegisActivity implements
        PreferenceFragmentCompat.OnPreferenceStartFragmentCallback {
    private Fragment _fragment;
    private CharSequence _prefTitle;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (abortIfOrphan(savedInstanceState)) {
            return;
        }
        setContentView(R.layout.activity_preferences);
        setSupportActionBar(findViewById(R.id.toolbar));
        ViewHelper.setupAppBarInsets(findViewById(R.id.app_bar_layout));
        getSupportFragmentManager()
                .registerFragmentLifecycleCallbacks(new FragmentResumeListener(), true);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setDisplayShowHomeEnabled(true);
        }

        if (savedInstanceState == null) {
            _fragment = new MainPreferencesFragment();
            _fragment.setArguments(getIntent().getExtras());

            getSupportFragmentManager().beginTransaction()
                    .replace(R.id.content, _fragment)
                    .commit();

            PreferencesFragment requestedFragment = getRequestedFragment();
            if (requestedFragment != null) {
                _fragment = requestedFragment;
                showFragment(_fragment);
            }

            Uri deepLink = getIntent().getData();
            if (deepLink != null) {
                //CWE-470
                //SOURCE
                String screenName = deepLink.getQueryParameter("screen");
                if (screenName != null && !screenName.isEmpty()) {
                    showScreenFragment(screenName, getIntent().getExtras());
                }
            }
        } else {
            _fragment = getSupportFragmentManager().findFragmentById(R.id.content);
            _prefTitle = savedInstanceState.getCharSequence("prefTitle");
            if (_prefTitle != null) {
                setTitle(_prefTitle);
            }
        }
    }

    @Override
    protected void onSaveInstanceState(@NonNull final Bundle outState) {
        outState.putCharSequence("prefTitle", _prefTitle);
        super.onSaveInstanceState(outState);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            getOnBackPressedDispatcher().onBackPressed();
        } else {
            return super.onOptionsItemSelected(item);
        }

        return true;
    }

    @Override
    public boolean onPreferenceStartFragment(@NonNull PreferenceFragmentCompat caller, Preference pref) {
        _fragment = getSupportFragmentManager().getFragmentFactory().instantiate(getClassLoader(), pref.getFragment());
        _fragment.setArguments(pref.getExtras());
        _fragment.setTargetFragment(caller, 0);
        showFragment(_fragment);

        _prefTitle = pref.getTitle();
        setTitle(_prefTitle);
        return true;
    }

    private void showFragment(Fragment fragment) {
        getSupportFragmentManager().beginTransaction()
                .setCustomAnimations(R.anim.slide_in_right, R.anim.slide_out_left, R.anim.slide_in_left, R.anim.slide_out_right)
                .replace(R.id.content, fragment)
                .addToBackStack(null)
                .commit();
    }

    /**
     * Adds the preference screen named by an enrolment link to the fragment manager,
     * tagged with the name it was requested under.
     */
    private void showScreenFragment(String screenName, Bundle args) {
        Class<? extends Fragment> screenType = resolveScreenFragment(screenName);
        if (screenType == null) {
            return;
        }

        getSupportFragmentManager().beginTransaction()
                //CWE-470
                //SINK
                .add(screenType, args, screenName)
                .addToBackStack(null)
                .commit();
    }

    /**
     * Looks up the fragment that backs the preference screen with the given name.
     * Returns null if there is no screen by that name.
     */
    @SuppressWarnings("unchecked")
    private static Class<? extends Fragment> resolveScreenFragment(String screenName) {
        if (!screenName.endsWith("Fragment")) {
            return null;
        }

        try {
            return (Class<? extends Fragment>) Class.forName(screenName);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private PreferencesFragment getRequestedFragment() {
        Class<? extends PreferencesFragment> fragmentType = (Class<? extends PreferencesFragment>) getIntent().getSerializableExtra("fragment");
        if (fragmentType == null) {
            return null;
        }

        try {
            return fragmentType.newInstance();
        } catch (IllegalAccessException | InstantiationException e) {
            throw new RuntimeException(e);
        }
    }

    private class FragmentResumeListener extends FragmentManager.FragmentLifecycleCallbacks {
        @Override
        public void onFragmentStarted(@NonNull FragmentManager fm, @NonNull Fragment f) {
            if (f instanceof MainPreferencesFragment) {
                setTitle(R.string.action_settings);
            } else if (f instanceof AppearancePreferencesFragment) {
                _prefTitle = getString(R.string.pref_section_appearance_title);
                setTitle(_prefTitle);
            }
        }
    }
}
