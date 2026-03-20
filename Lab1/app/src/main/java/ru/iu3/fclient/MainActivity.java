package ru.iu3.fclient;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import ru.iu3.fclient.databinding.ActivityMainBinding;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements TransactionEvents {

    static {
        System.loadLibrary("fclient");
        System.loadLibrary("mbedcrypto");
    }

    private ActivityMainBinding binding;
    private String pin;
    ActivityResultLauncher activityResultLauncher;

    public static byte[] stringToHex(String s) {
        byte[] hex;
        try {
            hex = Hex.decodeHex(s.toCharArray());
        } catch (DecoderException ex) {
            hex = null;
        }
        return hex;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        initRng();
        byte[] key = new byte[16];
        byte[] data1 = "Test message".getBytes();
        byte[] enc = encrypt(key, data1);
        byte[] dec = decrypt(key, enc);

        Log.d("fclient_test", "Original: " + new String(data1));
        // Log.d("fclient_test", "HEX: " + Hex.encodeHexString(enc));
        Log.d("fclient_test", "Decrypted: " + new String(dec));

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());

        activityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent data = result.getData();
                        assert data != null;
                        pin = data.getStringExtra("pin");
                        synchronized (MainActivity.this) {
                            MainActivity.this.notifyAll();
                        }
                    }
                });
    }

    public void onButtonClick(View v) {
        new Thread(()-> {
            try {
                byte[] trd = stringToHex("9F0206000000000100");
                boolean ok = transaction(trd);
                runOnUiThread(()-> {
                    Toast.makeText(MainActivity.this, ok ? "ok" : "failed", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception ex) {
                // todo: log error
            }
        }).start();
    }

    public native String stringFromJNI();
    public static native int initRng();
    public static native byte[] randomBytes(int no);

    public native byte[] encrypt(byte[] key, byte[] data);
    public native byte[] decrypt(byte[] key, byte[] data);

    public native boolean transaction(byte[] trd);

    @Override
    public String enterPin(int ptc, String amount) {
        pin = new String();
        Intent it = new Intent(MainActivity.this, PinpadActivity.class);
        it.putExtra("ptc", ptc);
        it.putExtra("amount", amount);
        synchronized (MainActivity.this) {
            activityResultLauncher.launch(it);
            try {
                MainActivity.this.wait();
            } catch (Exception ex) {
                //todo: log error
            }
        }
        return pin;
    }

    @Override
    public void transactionResult(boolean result) {
        runOnUiThread(()-> {
            Toast.makeText(MainActivity.this, result ? "ok" : "failed", Toast.LENGTH_SHORT).show();
        });
    }
}